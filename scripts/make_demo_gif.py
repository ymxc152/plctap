# -*- coding: utf-8 -*-
"""生成 docs/demo.gif: 用真实 plctap 工具调用数据渲染聊天式演示动画。

用法 (仓库根目录):
    uv run --with pillow python scripts/make_demo_gif.py

- 内嵌最小 Modbus TCP 从站 (纯 asyncio, 无外部依赖), 预置与联测相同的数据
- 工具调用全部真实执行, 渲染层只负责画图
"""
from __future__ import annotations

import asyncio
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from plctap.config import PlctapConfig  # noqa: E402
from plctap.conn.manager import ConnectionPool  # noqa: E402
from plctap.models import Target  # noqa: E402
from plctap.protocols.modbus.adapter import ModbusAdapter, ModbusError  # noqa: E402

TARGET = Target(protocol="modbus", host="127.0.0.1", port=15210, unit=1)

# ---------------------------------------------------------------- 内嵌从站


class DemoSlave:
    """最小状态化从站: fc03 读 / fc05-06 写 (写后状态可读回)。"""

    def __init__(self) -> None:
        self.regs: dict[int, int] = {1: 1234, 2: 5678, 3: 0xFFFF}  # 预置, 与实机联测一致

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = await r.readexactly(7)
                length = struct.unpack_from(">H", head, 4)[0]
                rest = await r.readexactly(length - 1)
                fc = rest[0]
                addr = struct.unpack_from(">H", rest, 1)[0]
                if fc == 3:  # 读保持寄存器
                    qty = struct.unpack_from(">H", rest, 3)[0]
                    vals = [self.regs.get(addr + i, 0) for i in range(qty)]
                    data = b"".join(struct.pack(">H", v) for v in vals)
                    pdu = struct.pack(">BB", fc, len(data)) + data
                elif fc in (5, 6):  # 写: 回显 + 更新状态
                    value = struct.unpack_from(">H", rest, 3)[0]
                    self.regs[addr] = 1 if (fc == 5 and value) else value
                    pdu = rest
                else:
                    pdu = bytes([fc | 0x80, 0x01])
                w.write(head[:4] + struct.pack(">H", len(pdu) + 1) + head[6:7] + pdu)
                await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            return


# ---------------------------------------------------------------- 真实调用


def gather_transcript() -> list[tuple[str, list[str]]]:
    """跑真实工具调用, 产出 (role, lines) 转写。"""

    async def run() -> list[tuple[str, list[str]]]:
        slave = DemoSlave()
        port = await slave.start()
        tgt = Target(protocol="modbus", host="127.0.0.1", port=port, unit=1)
        adapter = ModbusAdapter(ConnectionPool(), PlctapConfig())
        t: list[tuple[str, list[str]]] = []

        # 1) 分层定位
        probe = await adapter.probe(tgt)
        t.append(("user", ["设备 127.0.0.1 在线吗? 读不到数据。"]))
        t.append(("agent", [
            "调用 probe_device -> 分层定位:",
            json.dumps({"reachable": probe.reachable, "layer_hint": probe.layer_hint}, ensure_ascii=False),
            "TCP 与协议栈正常, 继续读数。",
        ]))

        # 2) 读寄存器
        r = await adapter.read(tgt, address=1, count=3, datatype="uint16")
        t.append(("user", ["读保持寄存器 addr 1-3"]))
        t.append(("agent", [
            "调用 plc_read (fc03):",
            f"> {r.request_frame}",
            json.dumps({"raw": r.raw_registers, "interpreted": r.interpreted}, ensure_ascii=False),
        ]))

        # 3) 写 float32 + 读回
        await adapter.write(tgt, address=11, values=[0x4049])
        w2 = await adapter.write(tgt, address=12, values=[0x0FDB])
        rf = await adapter.read(tgt, address=11, count=2, datatype="float32", byteorder="big")
        t.append(("user", ["把 3.14 写到 addr 11 (float32, 大端)"]))
        t.append(("agent", [
            f"调用 plc_write (fc06) x2 -> {w2['request_frame']}",
            "读回验证:",
            json.dumps({"float32": rf.interpreted}, ensure_ascii=False),
            "写入成功, 值为 3.1415927。",
        ]))

        # 4) 越界 -> 异常归因
        try:
            await adapter.read(tgt, address=200, count=1)
        except ModbusError as e:
            t.append(("user", ["那 addr 200 呢?"]))
            t.append(("agent", [
                "设备返回异常:",
                str(e),
                "建议: 确认该设备寄存器区范围后再读 (应用层配置问题)。",
            ]))
        await slave.stop()
        return t

    return asyncio.run(run())


# ---------------------------------------------------------------- 渲染

W, H = 880, 620
BG = (24, 24, 38)
PANEL = (32, 32, 50)
USER_BG = (57, 73, 171)
AGENT_BG = (44, 44, 66)
GREEN = (128, 222, 160)
BLUE = (130, 200, 255)
YELLOW = (255, 224, 130)
GREY = (150, 150, 170)


def render_gif(transcript: list[tuple[str, list[str]]], out: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    def font(size: int, bold: bool = False):
        name = "msyhbd.ttc" if bold else "msyh.ttc"  # 中文用雅黑 (Consolas 无 CJK 字形)
        try:
            return ImageFont.truetype(f"C:/Windows/Fonts/{name}", size)
        except OSError:
            return ImageFont.load_default()

    f_title, f_body, f_mono = font(22, True), font(16), font(14)

    def wrap(s: str, width: int) -> list[str]:
        return [s[i : i + width] for i in range(0, len(s), width)] or [""]

    frames: list[Image.Image] = []

    def bubble(draw, y, role, lines):
        is_user = role == "user"
        maxw = 78
        wrapped = []
        for ln in lines:
            if any(ch in ln for ch in "{}[]"):
                wrapped += wrap(ln, maxw - 4)
            else:
                wrapped += wrap(ln, maxw - 8)
        h = 18 + len(wrapped) * 21
        x0 = W - 500 - 30 if is_user else 30
        x1 = x0 + (500 if is_user else 700)
        draw.rounded_rectangle([x0, y, x1, y + h], radius=12,
                               fill=USER_BG if is_user else AGENT_BG,
                               outline=(80, 80, 110), width=1)
        yy = y + 8
        for ln in wrapped:
            mono = any(ch in ln for ch in "{}[]<>")
            color = (255, 255, 255) if is_user else (GREEN if ln.startswith(">") else BLUE)
            if "建议" in ln or "写入成功" in ln:
                color = YELLOW
            draw.text((x0 + 14, yy), ln, font=f_mono if mono else f_body, fill=color)
            yy += 21
        return y + h + 14

    # 帧渐进: 每帧多显示一条消息 (第 i 帧显示 transcript[:i+1] 完整重绘)
    steps = [(role, lines) for role, lines in transcript]
    for i, (role, lines) in enumerate(steps):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, 46], fill=PANEL)
        d.text((20, 11), "plctap — Agent 的 PLC 驱动层 (Modbus TCP 演示, 真实数据)", font=f_title, fill=(235, 235, 245))
        y = 62
        for j in range(i + 1):
            r, ls = steps[j]
            y = bubble(d, y, r, ls)
            if y > H - 30:
                y = bubble(d, y, r, ls)  # 越界兜底 (内容较长时可能截断)
        if i == len(steps) - 1:
            d.rounded_rectangle([30, H - 64, W - 30, H - 18], radius=10, fill=PANEL)
            d.text((46, H - 55), "github.com/<you>/plctap · write -> read -> interpret 闭环 · Modbus/FINS/MELSEC",
                   font=f_body, fill=GREY)
        frames.append(img)

    frames[0].save(out, save_all=True, append_images=frames[1:], duration=2800, loop=0, optimize=True)
    frames[-1].save(out.with_suffix(".png"))  # 静态预览 (README 备用/人工 QA)


def main() -> None:
    out_dir = ROOT / "docs"
    out_dir.mkdir(exist_ok=True)
    transcript = gather_transcript()
    render_gif(transcript, out_dir / "demo.gif")
    print(f"OK: {out_dir / 'demo.gif'} ({(out_dir / 'demo.gif').stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
