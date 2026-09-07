# -*- coding: utf-8 -*-
"""生成 docs/demo.gif: 用真实 plctap 工具调用数据渲染聊天式演示动画。

用法 (仓库根目录):
    .venv/Scripts/python.exe scripts/make_demo_gif.py

- 内嵌最小 Modbus TCP 从站 (纯 asyncio, 无外部依赖), 预置与联测相同的数据
- detect 场景复用 eval/fakes.py 的进程内假设备 (与 benchmark detect 档同源)
- EtherNet/IP 场景按 tests/e2e 先例用 importlib 按文件路径加载
  tests/test_adapter_enip.py 的进程内假服务器 (tests/ 非可导入包)
- 钓鱼监听场景真实调用 plctap.listener.ListenerRegistry (record_only),
  脚本内 raw socket 客户端扮演"只当 client"的设备, 帧用 modbus codec
  build 纯函数构造, 收帧解析走 parse_auto (与 parse_frame 工具同轨)
- 工具调用全部真实执行, 渲染层只负责画图
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from plctap.config import PlctapConfig  # noqa: E402
from plctap.conn.manager import ConnectionPool  # noqa: E402
from plctap.listener import ListenerRegistry  # noqa: E402
from plctap.models import Target  # noqa: E402
from plctap.protocols.auto import parse_auto  # noqa: E402
from plctap.protocols.detect import DeviceDetector  # noqa: E402
from plctap.protocols.enip.adapter import EnipAdapter  # noqa: E402
from plctap.protocols.fins import adapter as _fins  # noqa: E402,F401  import 副作用登记注册表
from plctap.protocols.melsec import adapter as _mc  # noqa: E402,F401
from plctap.protocols.modbus import codec as modbus_codec  # noqa: E402
from plctap.protocols.modbus.adapter import ModbusAdapter, ModbusError  # noqa: E402
from plctap.protocols.s7 import adapter as _s7  # noqa: E402,F401

import fakes as eval_fakes  # noqa: E402

TARGET = Target(protocol="modbus", host="127.0.0.1", port=15210, unit=1)

# ---------------------------------------------------------------- 内嵌从站


class DemoSlave:
    """最小状态化从站: fc03 读 / fc05-06-16 写 / 越界回 0x02 异常。"""

    LIMIT = 100  # 模拟设备寄存器区上限, 越界回 ILLEGAL_DATA_ADDRESS

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
                    if addr + qty > self.LIMIT:
                        pdu = bytes([fc | 0x80, 0x02])
                    else:
                        vals = [self.regs.get(addr + i, 0) for i in range(qty)]
                        data = b"".join(struct.pack(">H", v) for v in vals)
                        pdu = struct.pack(">BB", fc, len(data)) + data
                elif fc == 16:  # 批量写寄存器 (v0.4 默认写语义); rest[5]=bytecount, 数据从 rest[6] 起
                    qty = struct.unpack_from(">H", rest, 3)[0]
                    if addr + qty > self.LIMIT:
                        pdu = bytes([fc | 0x80, 0x02])
                    else:
                        data = rest[6 : 6 + qty * 2]
                        for i in range(qty):
                            self.regs[addr + i] = struct.unpack_from(">H", data, i * 2)[0]
                        pdu = struct.pack(">BHH", fc, addr, qty)
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


def _load_fake_enip_server():
    """tests/ 非可导入包 (无 __init__.py), 按 tests/e2e 先例按文件路径加载。"""
    path = ROOT / "tests" / "test_adapter_enip.py"
    spec = importlib.util.spec_from_file_location("_fake_enip_for_demo", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.FakeEnipServer


async def _wait_frames(reg: ListenerRegistry, port: int, n: int, timeout: float = 3.0) -> list[dict]:
    """轮询等监听器收满 n 帧 (get_listener_frames 的进程内同款读取)。"""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        frames = reg.frames(port)
        if len(frames) >= n:
            return frames
        await asyncio.sleep(0.02)
    return reg.frames(port)


def gather_transcript() -> list[tuple[str, list[str]]]:
    """跑真实工具调用, 产出 (role, lines) 转写。"""

    async def run() -> list[tuple[str, list[str]]]:
        slave = DemoSlave()
        port = await slave.start()
        tgt = Target(protocol="modbus", host="127.0.0.1", port=port, unit=1)
        adapter = ModbusAdapter(ConnectionPool(), PlctapConfig())
        t: list[tuple[str, list[str]]] = []

        # 1) 协议自动识别 (冷启动: 只知道 IP, 不知道协议/端口)
        fake, _h, port_d = await eval_fakes.start_fake({"kind": "melsec", "port": 0, "name": "demo"})
        pool = ConnectionPool()
        try:
            detector = DeviceDetector(pool, PlctapConfig(default_timeout_ms=1000), adapters=None)
            result = await detector.detect(host="127.0.0.1", ports=[port_d], timeout_ms=None, deep=True)
        finally:
            await pool.close_all()
            await fake.stop()
        top = result.candidates[0]
        t.append(("user", ["手头就一台设备 127.0.0.1, 协议和端口都不知道, 从哪开始?"]))
        t.append(("agent", [
            "调用 detect_device (并发扫标准端口 -> 协议指纹 -> 验证读):",
            json.dumps({"protocol": top.protocol, "port": top.port, "confidence": top.confidence}, ensure_ascii=False),
            f"下一步: {top.next_step}",
            "零先验配置, 一次探测完成协议识别。",
        ]))

        # 2) 分层定位
        probe = await adapter.probe(tgt)
        t.append(("user", ["这台 Modbus 从站在线吗? 读不到数据。"]))
        t.append(("agent", [
            "调用 probe_device -> 分层定位:",
            json.dumps({"reachable": probe.reachable, "layer_hint": probe.layer_hint}, ensure_ascii=False),
            "TCP 与协议栈正常, 继续读数。",
        ]))

        # 3) 读寄存器
        r = await adapter.read(tgt, address=1, count=3, datatype="uint16")
        t.append(("user", ["读保持寄存器 addr 1-3"]))
        t.append(("agent", [
            "调用 plc_read (fc03):",
            f"> {r.request_frame}",
            json.dumps({"raw": r.raw_registers, "interpreted": r.interpreted}, ensure_ascii=False),
        ]))

        # 4) 写 float32 + 读回
        await adapter.write(tgt, address=11, values=[0x4049])
        w2 = await adapter.write(tgt, address=12, values=[0x0FDB])
        rf = await adapter.read(tgt, address=11, count=2, datatype="float32", byteorder="big")
        t.append(("user", ["把 3.14 写到 addr 11 (float32, 大端)"]))
        t.append(("agent", [
            f"调用 plc_write (fc16) x2 -> {w2['request_frame']}",
            "读回验证:",
            json.dumps({"float32": rf.interpreted}, ensure_ascii=False),
            "写入成功, 值为 3.1415927。",
        ]))

        # 5) 越界 -> 异常归因
        try:
            await adapter.read(tgt, address=200, count=1)
        except ModbusError as e:
            t.append(("user", ["那 addr 200 呢?"]))
            t.append(("agent", [
                "设备返回异常:",
                str(e),
                "建议: 确认该设备寄存器区范围后再读 (应用层配置问题)。",
            ]))

        # 6) EtherNet/IP tag 读 (进程内假服务器: importlib 复用适配器测试 fixture)
        FakeEnipServer = _load_fake_enip_server()
        enip = FakeEnipServer()
        host_e, port_e = await enip.start()
        pool_e = ConnectionPool()
        try:
            enip_adapter = EnipAdapter(pool_e, PlctapConfig())
            tgt_e = Target(protocol="enip", host=host_e, port=port_e, unit=1)
            re_ = await enip_adapter.read(tgt_e, "alpha[0]", 3, datatype="dint")
        finally:
            await pool_e.close_all()
            await enip.stop()
        t.append(("user", ["对面还有台 Rockwell 的设备, 走 EtherNet/IP, 读个 tag 看看?"]))
        t.append(("agent", [
            "调用 plc_read (CIP Read Tag, tag=alpha[0]):",
            json.dumps({"raw": re_.raw_registers, "interpreted": re_.interpreted}, ensure_ascii=False),
            "DINT 数组按双字小端拆解, 读回 [42, 43, 44], tag 直读闭环。",
        ]))

        # 7+8) 钓鱼监听: 设备只当 client, 起假 server 钓它的帧行为 (record_only)
        reg = ListenerRegistry()
        info = await reg.start("modbus", "127.0.0.1", 0, "record_only")
        lport = info["port"]
        reqs = [  # codec build 纯函数构造的设备侧请求帧
            modbus_codec.build_read_request(7, 1, 3, 0, 2),    # fc03 轮询读 addr 0-1
            modbus_codec.build_read_request(8, 1, 3, 100, 1),  # fc03 读 addr 100
            modbus_codec.build_write_single(9, 1, 6, 5, 314),  # fc06 写 addr 5
        ]
        reader, writer = await asyncio.open_connection("127.0.0.1", lport)
        for req in reqs:  # 脚本内 raw socket 客户端扮演"只出不进"的设备
            writer.write(req)
            await writer.drain()
            await asyncio.sleep(0.1)  # 分帧: 防止两帧并在一次 read 里被吞
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass
        cap = await _wait_frames(reg, lport, len(reqs))
        summary = await reg.stop(lport)
        first = parse_auto("modbus", bytes.fromhex(cap[0]["frame_hex"]))  # 与 parse_frame 同轨
        pfields = {f.name: f.value for f in first.fields}
        slim = {k: pfields[k] for k in ("unit_id", "function_code", "address", "quantity") if k in pfields}
        t.append(("user", ["还有台老网关只出不进, 只当 client, 我连不上它怎么办?"]))
        t.append(("agent", [
            "调用 start_listener (钓鱼模式, 立假 server 等它上钩):",
            json.dumps({"protocol": info["protocol"], "port": info["port"], "mode": info["mode"]}, ensure_ascii=False),
            "record_only: 只收帧不回话, 被动钓它的真实行为。",
        ]))
        t.append(("user", ["设备连上来了, 吐了几帧就断开。"]))
        t.append(("agent", [
            "调用 get_listener_frames -> parse_frame:",
            f"> {cap[0]['frame_hex']}",
            json.dumps({"valid": first.valid, **slim}, ensure_ascii=False),
            f"钓到了: fc03 读 + fc06 写都录下来 (共 {summary['recorded']} 帧), stop_listener 收工。",
        ]))

        await slave.stop()
        return t

    return asyncio.run(run())


# ---------------------------------------------------------------- 渲染

W, H = 880, 980
BG = (24, 24, 38)
PANEL = (32, 32, 50)
USER_BG = (57, 73, 171)
AGENT_BG = (44, 44, 66)
GREEN = (128, 222, 160)
BLUE = (130, 200, 255)
YELLOW = (255, 224, 130)
GREY = (150, 150, 170)

FOOTER = "github.com/ymxc152/plctap · detect/read/write/listen · Modbus/FINS/MELSEC/S7/IEC 104/EtherNet/IP"


def render_gif(transcript: list[tuple[str, list[str]]], out: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    def font(size: int, bold: bool = False):
        name = "msyhbd.ttc" if bold else "msyh.ttc"  # 中文用雅黑 (Consolas 无 CJK 字形)
        try:
            return ImageFont.truetype(f"C:/Windows/Fonts/{name}", size)
        except OSError:
            return ImageFont.load_default()

    f_title, f_body, f_mono = font(22, True), font(16), font(14)

    # 像素级换行 (中英混排按实测宽度, 不再按字符数估算)
    measure = ImageDraw.Draw(Image.new("RGB", (8, 8)))

    def wrap(s: str, fnt, maxw: int) -> list[str]:
        lines, cur = [], ""
        for ch in s:
            if cur and measure.textlength(cur + ch, font=fnt) > maxw:
                lines.append(cur)
                cur = ch
            else:
                cur += ch
        lines.append(cur or "")
        return lines

    # 预排版: 每条消息 -> [(文本段, 是否等宽)], 及气泡高度
    def msg_segs(role: str, lines: list[str]) -> list[tuple[str, bool]]:
        maxw = 472 if role == "user" else 672  # 气泡内宽 (像素)
        segs: list[tuple[str, bool]] = []
        for ln in lines:
            mono = any(ch in ln for ch in "{}[]<>")
            segs += [(seg, mono) for seg in wrap(ln, f_mono if mono else f_body, maxw)]
        return segs

    layout = [(role, msg_segs(role, lines)) for role, lines in transcript]
    heights = [18 + len(segs) * 21 + 14 for _, segs in layout]  # 气泡高 + 间距

    def draw_bubble(d, y, role, segs) -> None:
        is_user = role == "user"
        h = 18 + len(segs) * 21
        x0 = W - 500 - 30 if is_user else 30
        x1 = x0 + (500 if is_user else 700)
        d.rounded_rectangle([x0, y, x1, y + h], radius=12,
                            fill=USER_BG if is_user else AGENT_BG,
                            outline=(80, 80, 110), width=1)
        yy = y + 8
        for seg, mono in segs:
            color = (255, 255, 255) if is_user else (GREEN if seg.startswith(">") else BLUE)
            if "建议" in seg or "写入成功" in seg or "钓到了" in seg:
                color = YELLOW
            d.text((x0 + 14, yy), seg, font=f_mono if mono else f_body, fill=color)
            yy += 21

    # 帧渐进: 每帧多显示一条消息 (第 i 帧显示 transcript[:i+1] 完整重绘);
    # 内容超过可视区时像聊天窗口一样上滚, 保证最新消息可见
    n = len(layout)
    frames: list[Image.Image] = []
    for i in range(n):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        bottom_limit = H - 70 if i == n - 1 else H - 30  # 末帧给落款留位
        ys, y = [], 62
        for k in range(i + 1):
            ys.append(y)
            y += heights[k]
        content_bottom = ys[-1] + heights[i] - 14
        scroll = max(0, content_bottom - bottom_limit)
        for k in range(i + 1):
            top = ys[k] - scroll
            if top + heights[k] < 46:
                continue  # 已滚出标题栏上方
            draw_bubble(d, top, layout[k][0], layout[k][1])
        d.rectangle([0, 0, W, 46], fill=PANEL)  # 标题栏后画, 滚动的气泡从其下方穿过
        d.text((20, 11), "plctap — Agent 的 PLC 驱动层 (真实工具调用演示)", font=f_title, fill=(235, 235, 245))
        if i == n - 1:
            d.rounded_rectangle([30, H - 64, W - 30, H - 18], radius=10, fill=PANEL)
            d.text((46, H - 55), FOOTER, font=f_body, fill=GREY)
        frames.append(img)

    frames[0].save(out, save_all=True, append_images=frames[1:], duration=2800, loop=0, optimize=True)
    frames[-1].save(out.with_suffix(".png"))  # 静态预览 (README 备用/人工 QA)


def main() -> None:
    out_dir = ROOT / "docs"
    out_dir.mkdir(exist_ok=True)
    transcript = gather_transcript()
    render_gif(transcript, out_dir / "demo.gif")
    gif, png = out_dir / "demo.gif", out_dir / "demo.png"
    print(f"OK: {gif} ({gif.stat().st_size // 1024} KB) + {png} ({png.stat().st_size // 1024} KB), "
          f"{len(transcript)} 条消息")


if __name__ == "__main__":
    main()
