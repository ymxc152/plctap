# 发布清单 (GitHub / PyPI / MCP 收录站)

> 目标: 一条命令链把 `uvx plctap` 推到全网可装。所有代码侧准备已完成,
> 本文只列**你需要做的一次性前置**和**每次发版的固定动作**, 并解释每步为什么。

## 总体流程 (先看这个)

```
一次性前置 (只做一次):
  GitHub 建仓  +  PyPI 建项目并开 trusted publishing  +  收录站注册账号

每次发版 (5 分钟):
  bump version -> uv build 本地自检 -> git tag vX.Y.Z -> push -> CI 自动发 PyPI
```

## 阶段 0: 一次性前置

### 0.1 GitHub 仓库
- 用 `gh repo create ymxc152/plctap --public --source . --push`
  (或网页建空仓后 `git remote add origin git@github.com:ymxc152/plctap.git && git push -u origin main`)
- 仓库设置里填:
  - **Description** (建议): `Agent 的 PLC 驱动层 — Modbus TCP / FINS / MELSEC 的 MCP Server (探测/读写/报文诊断)`
  - **Topics** (建议): `mcp, modbus, fins, melsec, plc, industrial-automation, agent, fastmcp, scada`
- CI 已在 `.github/workflows/ci.yml` (push/PR 跑全量 pytest), 推上去就自动绿

### 0.2 PyPI 项目
- 到 https://pypi.org 注册, 建项目名 **plctap** (与包名一致)
- 推荐用 **Trusted Publishing** (OIDC): 不用记 token, GitHub Actions 自动换凭证。
  一次性设置: PyPI 项目 Settings → "Publishing" → 填 `GitHub` / 你的仓库 / `publish` (workflow 文件名)
- 备选: 本地 `uvx twine upload` (需要 `PYPI_TOKEN`, 每次发版手动跑)

### 0.3 MCP 收录站账号 (最后做也行)
glama.ai / mcp.so / Pulse (npm 的 mcp-registry) 各注册一个账号。

## 阶段 1: 每次发版 (固定动作)

```bash
# 1) bump 版本 (0.x 阶段手动改 pyproject.toml 的 version)
# 2) 本地自检: 构建 + 冒烟
uv build
uv run python -m pytest -q          # 全量测试
uvx --from . plctap                  # 控制台入口能启动 (stdio 挂起=正常)
# 3) 提交 + 打标签 + 推送
git add pyproject.toml && git commit -m "release: vX.Y.Z"
git tag vX.Y.Z && git push origin main --tags
# 4) CI 自动: 构建 -> publish workflow 上传 PyPI (OIDC, 无密钥)
# 5) 验收
uvx plctap                           # 任意机器一行装起来
```

### 版本号约定
- 0.1.x: alpha, 每次有可发布增量就 tag
- 1.0: 语义定稿 (READme 评测对比表 + 双端截图齐了之后)

## Skill 的安装方式 (重点, 与包分开)

`skill/SKILL.md` **不进 wheel**, 原因是 skill 是客户端侧的指令文件, 不是运行时
依赖 —— 用户/Agent 是"复制"不是"pip 装"。随 sdist 与 GitHub 仓库分发:

```bash
mkdir -p ~/.claude/skills
cp skill/SKILL.md ~/.claude/skills/
```

README 里补一句即可。若以后想在 `uvx` 后一行装 skill, 再加一个
`plctap install-skill` 子命令 (M4 范围)。

## 阶段 2: 补全内容 (需你的环境)

- [ ] 三端接入截图 (Claude Desktop / Codex / Cursor), 替换 README 占位
- [ ] 五档评测对比表: `eval/benchmark.py` 工具模式已 18/18; 裸模型基线
      `uv run python eval/baseline.py --run` (需 `OPENAI_API_KEY`), 出对比表
- [ ] README 首屏加 CI 徽章 (仓库公开后): `![CI](https://github.com/ymxc152/plctap/actions/workflows/ci.yml/badge.svg)`

## 阶段 3: MCP 收录站提交 (每个站一条)

- 提交内容: 名称 `plctap` / 一句话描述 / 服务器 URL (npm 的填 `plctap`)
- 描述建议: `Agent-PLC MCP server: probe, read, write and diagnose Modbus TCP / FINS / MELSEC PLCs`
- 三个站各自"提交"表单, 填完等收录 (一般 1-3 个工作日)

## 安全检查 (每次发版前过一遍)

- [ ] `git status` 无敏感文件 (`.claude/**` 已从 sdist 排除, 见 pyproject)
- [ ] `uv build` 后 `unzip -l dist/*.whl` 只含 plctap 包与 license
- [ ] README 里没有真实 IP / 型号组合 / 业务寄存器 (红线 1)
