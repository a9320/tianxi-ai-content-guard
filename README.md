# tianxi-ai-content-guard

AI 内容安检（`ai-content-guard`）——面向天禧 Claw / 联想浏览器 / 如意的纯本地、零网络内容安检 skill：检测提示注入、隐形字符走私、多层编码载荷、AI 配置文件后门。

> **核心原则：engine verdicts, model explains.**
> 确定性引擎出判决与脱敏证据，宿主模型只做解释与措辞——模型漂移、拒答、被注入都不影响检测结果。

**状态**：v1.1.0（严格测试修复版，2026-10-25）——中文/劫持覆盖层、全量路由、file 防护、全链路脱敏。

## 仓库结构

| 目录 | 内容 |
|---|---|
| `skill/` | skill 包源（SKILL.md / entry.py / scripts / references），按天禧规范打包 |
| `build/` | 双渠道构建变体（天禧 `${QODER_SKILL_DIR}` / ClawHub `{baseDir}`） |
| `benchmark/` | 30×3 触发基准 harness（用例集 + session JSONL 分析器） |
| `vendor/` | 自 arcanum-spark vendor 的 PITAX 引擎副本 + hash 同步锚 |
| `docs/` | 平台规范要点 / 设计决策 / 基准规范 |

## 相关仓库

- [arcanum-spark](https://github.com/a9320/arcanum-spark) — 引擎源头与 6-Agent 审计管线（深度审计 Pro path）
- [tianxi-skills](https://github.com/a9320/tianxi-skills) — 团队天禧 skill 系列（phish-guard / privacy-scanner / dependency-audit / seccode-tutor…），本 skill 与 phish-guard 互补：他们管"链接是不是钓鱼"，我们管"内容是不是在坑你的 AI"

## 安全与许可

- 纯标准库、零第三方依赖、零网络、只读扫描、毫秒级
- 规则基于 [Arcanum Prompt Injection Taxonomy v1.6.1](https://arcanum-sec.com/pitax)（Jason Haddix, CC BY 4.0）派生，署名随包
- 代码许可：MIT
