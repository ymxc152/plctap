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
  - **Description** (建议, 已按七协议更新): `Agent 的 PLC 驱动层 — Modbus TCP/RTU / FINS / MELSEC / S7comm / IEC 104 / EtherNet/IP 的 MCP Server (探测/识别/读写/诊断)`
  - **Topics** (建议): `mcp, mcp-server, modelcontextprotocol, modbus, s7, s7comm, fins, melsec, iec60870, ethernet-ip, plc, industrial-automation, agent, fastmcp`
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
#    前提: 待发布提交必须先推分支过 CI, 且 tag 所在提交要包含最新 publish.yml
#    —— v0.5.3 曾从含旧版 workflow 的线上打 tag, 绕过了 guard-main 闸门
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
#            -> 创建 GitHub Release (notes 按 commits 自动生成, 可事后润色)
# 5) 验收
uvx plctap                           # 任意机器一行装起来
```

### 版本号约定与发布节奏（2026-09-07 起: 累积发布）
- **main 单主干累积**: 日常 commit/小分支直接进 main（每次 push CI 全量跑, main 永远是
  绿的"随时可发"状态）; **不打 tag 就不发版** —— bump 版本、tag、发布三步只发生在发版时刻
- **发版触发（满足其一）**: ① 一个里程碑/批次 DoD 达成 ② 累计窗口到 1~2 周
  ③ 需要紧急修复（不等累积, 单独发 patch）
- **版本号语义 (0.x 阶段)**: minor = 功能批次 (v0.6.0 = 产品化收官批次), patch = 修复 (v0.6.1)
- 累积期的变更账本 = commit 流 + PLAN.md 里程碑; 发版时 GitHub Release notes 自动按
  commits 生成, 值得讲的亮点 (如"台架抓出 S7 审计缺口")发版后手动润色到 release 页
- **稳定化纪律 (2026-09-08 起, 自 v0.6.1 生效)**: MCP 工具名/参数名/返回结构向后兼容,
  新增只增不改; 破坏性变更三处提前标注 (docstring/README/Release notes) —— 详见
  README「版本与兼容承诺」节。v0.6.1 为 patch (修复+稳定化), minor 留给下一个功能批次
- 1.0 (语义定稿): 稳定化纪律经过至少一个完整发布周期验证后另行宣布; 不预设时间表

### GitHub Release notes 规则（强制——Release 页面永不空白）
- 每次 tag 发版, CI (publish.yml 的 github-release job) 保证 Release 存在且 notes 非空:
  不存在则按 commit 前缀自动分类创建——✨ 新增/能力 (feat/add/新增) · 🐛 修复 (fix/修复) ·
  🔧 工程/CI/发布 (ci/chore/build/release/merge) · 📝 文档 (docs) · ♻️ 其他,
  末尾附 Full Changelog 比较链接; 区间无提交时兜底 --generate-notes
- **人工撰写的 notes 优先**: CI 只在 Release 不存在时创建, 绝不改写已有 Release ——
  发版时先写好叙事版 notes 即可, CI 是兜底不是覆盖者
- 发版 notes 写法参照 v0.5.5: 修复了什么 + 为什么全量测试没抓到 (方法学) + 流程升级 + 质量数字 + 安装命令
- **依赖 commit message 前缀规范** (fix:/docs:/ci:/feat:...) —— 自动分类质量取决于前缀, 杂乱前缀进"其他"
- 历史空 tag 可事后补录: 本地 `gh release create vX.Y.Z --verify-tag --title ... --notes-file`

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

## 阶段 3: 剩余收录站 (2026-09-07 定为观察项, 当前无待办动作)

- 官方 Registry (CI 自动, 0.4.0→0.5.5 多版本 active) 与 glama.ai (爬虫自动收录/同步版本) 均无需手动操作
- **mcp.so**: 实测仅 $39 付费档收录, 用户决策跳过; 若后续愿付费, 提交内容如下备用
- **Pulse**: 官方暂停接收 (其建议改投官方 Registry, 已在); 恢复后再评估
- 备用提交内容: 名称 `plctap` / 一句话描述 / 服务器 URL (PyPI 包填 `plctap`)
- 描述建议: `Agent-PLC MCP server: probe, detect, read, write and diagnose Modbus TCP/RTU, FINS, MELSEC, S7comm, IEC 104 and EtherNet/IP devices`

## 安全检查 (每次发版前过一遍)

- [ ] `git status` 无敏感文件 (`.claude/**` 已从 sdist 排除, 见 pyproject)
- [ ] `uv build` 后 `unzip -l dist/*.whl` 只含 plctap 包与 license
- [ ] README 里没有真实 IP / 型号组合 / 业务寄存器 (红线 1)
