# 天禧平台规范要点（工程速查）

> 证据来源：团队实测（7 个已上架 skill）+ 平台对接人解答 + 本机客户端二进制/日志取证（2026-10-24）。
> 结论有效期：客户端或模型目录升级后，标注 ★ 的常量需重新核对。

## 触发机制

- **无关键词/语义路由**。宿主把 skill 清单（`- name: description - whenToUse`）注入系统提示，模型自选是否读 SKILL.md。
- ★ description 与 whenToUse **拼接后**按 **300 JS 字符**硬截断；CJK 占 2 列。
- ★ 清单预算 = 180k × 3 列 × 0.05 = **27,000 显示列**（约 9k token）；超预算时低使用度 skill 降级为 name-only（约 43 个满长 skill 触发；我们个位数安全）。
- ★ 本机 Agent 循环模型 = `dfmodel`（DeepSeek-Flash，非推理、temp0、180k 输入、MoE）——**按弱快模型设计，判决权归引擎**。
- 中途安装：`/skills reload` → 新会话 → 重启客户端（三步递进引导）。
- description 写"当…时使用"描述式；**禁命令式**（"必须先读我"=注入审核红线）。

## 输出与上下文预算 ★

| 项 | 值 |
|---|---|
| 工具输出截断 | 40,000 字符（前 20% + 后 80%） |
| 落盘阈值 | >50,000 字符 → 只回 2,000 预览 |
| 有效输入窗口 | 180,000 tokens（auto-compact 另按 200k 判 50%/75%） |
| SKILL.md | 激活无硬截断；**≤300 行、核心协议前 80 行** |
| Read 工具 | 默认最多 2,000 行 |
| fork | 同模型独立上下文，maxTurns=10，只回最终文本；**不是沙箱** |

## 打包硬规则

- ZIP ≤ 10MB；**SKILL.md 必须在 ZIP 根目录**；单文件 ≤ 1MB（CLI 超限**静默跳过只 warning**→打包后必查内容）；只打包 12 类文本扩展名（**PNG 不进包**，图标走网页控制台）。
- 天禧包五件：SKILL.md + package.json + _meta.json + assets（网页端补）+ `.skill-config.json`（CLI 真正读的元数据：name/description/description_zh/version/updateNotes/ignore）。
- 版本号四处一致：.skill-config.json / SKILL.md / package.json / _meta.json。
- 每次推送 = 全量重审（约 5 个工作日）→ **批量发版**，semver 递增。

## 审核红线（实测）

1. 隐私声明必须逐条代码兑现；2. 禁字符串拼接规避扫描；3. 代码出现 `eval(`/`exec(` 即拦；4. 缺 assets 可能被打回（网页表单补齐）；5. ZIP 多套目录；6. 绝对化承诺（"100% 拦截"）；7. 外链导流/收集信息。

## 安全检测类降险十律

特征串外置 `references/rules/*.json` / 零宽字符 `\uXXXX` 转义存储 / 禁动态执行 / base64 限 3 层·64KB 入·256KB 出 / 不做反检测 / 命名中性（避 payload·exploit·bypass·weapon）/ 防御性说明放 `references/security-notes.md` / 提交时 updateNotes 报备 / 完整越狱句不进 SKILL.md 正文 / `--self-check` 自证。

## 运行环境

- ★ 天禧自带 Python 3.14.6 embeddable，**stdout/stdin 默认 GBK** → 必须 reconfigure UTF-8、stdin 按 utf-8-sig→utf-8→gb18030→utf-16 链解。
- Windows 用 `python` 勿用 `python3`（Store 占位符）。
- ★ 平台无注入硬拦截，会话可能 `bypassPermissions` 运行 → **工具白名单自己收窄**（frontmatter `allowed-tools`）。
- 占位符：天禧 `${QODER_SKILL_DIR}`，ClawHub `{baseDir}` → 单一源码+两构建变体。
