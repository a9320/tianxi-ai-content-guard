# OpenClaw 测试轮速查（Qwen3.8-Flash-Next）

## 安装

1. 取包：`dist/clawhub/ai-content-guard-1.2.1.zip`（`{baseDir}` 占位符变体）。
2. 解压到 OpenClaw 的 skill 目录（任一配置根 6 层内出现 SKILL.md 即被发现）：
   - 常见位置：`~/.openclaw/skills/ai-content-guard/`（本机 `~/.openclaw` 已存在）；
   - 或当前 workspace 下的 `skills/` 目录。
3. 验证：`/skills list`（或 `$` 搜索）里出现 `ai-content-guard`；不出现则新开会话/重启客户端。
4. 模型切到 Qwen3.8-Flash-Next（DashScope OpenAI 兼容端点）。

## 执行纪律（与天禧轮对齐，保证两轮可比）

- 用例=30 例（`benchmark/PROMPTS.md` 对照，fixture 在 `~/acg-bench/`），乱序；
- **每例新开会话**，每例 3 次；
- 判定只认 trace（会话里真实出现 entry.py 执行/`[ai-content-guard]` stderr 标记），
  不认模型自述；
- 负例若触发，额外记它调用了什么（误触发形态数据）；
- 记录实际模型名/版本与客户端版本（漂移探测锚）。

## 记录

手动勾 `benchmark/RESULT-SHEET.md`（30×3 复选框），发回后我算：
正向触发率（≥80% 达标）/ 负向误触发率（≤10%）/ 不稳定率（1-2/3 的用例占比 ≤20%）/ Wilson CI。

## 已知差异（记录时留意）

- OpenClaw 工具输出截断/清单预算与 qodercli 可能不同——若发现 skill 没被列出或
  description 被截，记下来（这是渠道差异数据，不是失败）。
- `{baseDir}` 在 OpenClaw 侧替换；若也不替换，SKILL.md §2 的 Base directory 兜底句生效。
