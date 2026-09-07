# 发布清单 (GitHub / PyPI / MCP 收录站)

> 目标: 一条命令链把 `uvx plctap` 推到全网可装。所有代码侧准备已完成,
> 本文只列**你需要做的一次性前置**和**每次发版的固定动作**, 并解释每步为什么。

## 总体流程 (先看这个)

```
一次性前置 (只做一次):
  GitHub 建仓  +  PyPI 建项目并开 trusted publishing  +  收录站注册账号

每次发版 (5 分钟):
  合入 main -> 在 main 上 bump pyproject version (直接编辑, 不用 sed 模式替换)
  -> uv build 本地自检 -> git tag vX.Y.Z -> git push origin refs/tags/vX.Y.Z
  -> CI 自动: guard-main 闸门 (tag 必须已在 main 历史内, 分支 tag 拒绝发布)
     -> 发 PyPI + 收录 MCP 官方 Registry (server.json 版本由 CI 对齐 tag)
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

### 0.3 MCP 官方 Registry (零前置) + 聚合收录站
- 官方 Registry (registry.modelcontextprotocol.io): **不用注册账号、无任何前置**。
  server.json 的 name `io.github.ymxc152/plctap` 就是 GitHub 身份声明, CI 里
  `mcp-publisher login github-oidc` 用 Actions OIDC 换凭证发布 (与 PyPI 一样无密钥)。
- glama.ai: **自动收录、自动更新, 发版零动作**。爬 GitHub/PyPI 自动发现并收录
  (plctap 未手动提交即被收录), 定期跑 MCP 巡检抓取工具 schema 变更并同步版本
  (v0.4.0 发布当日即同步)。无发布 API 可调, CI 无需任何步骤; 可选一次性在浏览器
  登录 GitHub 认领 (Claim) 该条目, 认领后可编辑描述/图标等元数据——与版本自动
  更新无关。
- mcp.so / Pulse: 需手动注册账号提交表单 (见阶段 3)。

## 阶段 1: 每次发版 (固定动作)

```bash
# 1) bump 版本 (0.x 阶段手动编辑 pyproject.toml 的 version; 不用 sed 模式替换
#    —— v0.5.2 曾因 sed 模式未匹配 0.5.1 导致 tag 校验失败、删 tag 重打)
# 2) 本地自检: 构建 + 冒烟
uv build
uv run python -m pytest -q          # 全量测试
uvx --from . plctap                  # 控制台入口能启动 (stdio 挂起=正常)
# 3) 提交 + 打标签 + 推送 (server.json 不用手动 bump, CI 自动对齐 tag)
#    发布闸门 (guard-main): 仅 main 历史内的 tag 触发发布 —— 先合入 main 再打 tag,
#    分支上的 tag 会被 CI 拒绝; tag 用显式 refspec 推送, 避免与同名分支歧义
#    (v0.5.2 教训)
git add pyproject.toml && git commit -m "release: vX.Y.Z"
git tag vX.Y.Z && git push origin refs/heads/main && git push origin refs/tags/vX.Y.Z
# 4) CI 自动: 版本一致性校验 -> 构建 -> 上传 PyPI (OIDC, 无密钥)
#            -> 等 PyPI 索引生效 -> mcp-publisher publish server.json 收录官方 Registry
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

## 阶段 2: 已结项 (2026-09-07)

- [x] 裸模型基线双跑完成, 五档对比表已进 README (工具 35/35 vs 裸模型 24/35; v0.4 起工具模式六档 39/39)
- [x] README 首屏徽章已加 (CI + PyPI 版本 + MCP Registry + License)
- [x] ~~三端接入截图~~ 取消: 接入配置样例已足够说明, 不再需要截图

## 阶段 3: 剩余收录站提交 (mcp.so / Pulse, 每站一条)

- 官方 Registry (CI 自动) 与 glama.ai (爬虫自动收录/更新) 均无需手动操作
- 提交内容: 名称 `plctap` / 一句话描述 / 服务器 URL (npm 的填 `plctap`)
- 描述建议: `Agent-PLC MCP server: probe, read, write and diagnose Modbus TCP / FINS / MELSEC / S7 PLCs`
- 两个站各自"提交"表单, 填完等收录 (一般 1-3 个工作日)

## 安全检查 (每次发版前过一遍)

- [ ] `git status` 无敏感文件 (`.claude/**` 已从 sdist 排除, 见 pyproject)
- [ ] `uv build` 后 `unzip -l dist/*.whl` 只含 plctap 包与 license
- [ ] README 里没有真实 IP / 型号组合 / 业务寄存器 (红线 1)
