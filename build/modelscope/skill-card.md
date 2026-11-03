## Description: <br>
AI 内容安检：检测文本、文件、网页与邮件中的提示注入、隐形字符走私、多层编码载荷和 AI 配置文件后门。纯本地确定性引擎，零网络、零第三方依赖、默认只读；输出四值判决（malicious / suspicious / clean / inconclusive）、脱敏证据与处置建议。 <br>

This skill is ready for commercial/non-commercial use. <br>

## Publisher: <br>
AI溢出安全实验室 · [github.com/a9320](https://github.com/a9320) <br>

### License/Terms of Use: <br>
MIT <br>

## Use Case: <br>
面向个人与团队在处理不可信外部内容前的安全检查：粘贴的文本、邮件正文、聊天记录、下载或克隆的文件与仓库、脚本与配置文件（含 `.cursor/rules`、`CLAUDE.md` 等 AI 配置）。典型触发场景为用户要求"检查有没有问题"、或在总结/翻译/解释/执行某个文件与仓库之前。适用于办公内容安全、AI 配置审计与提示注入排查。 <br>

### Deployment Geography for Use: <br>
Global <br>

## Known Risks and Mitigations: <br>
Risk: 检测基于确定性的规则与模式匹配，可能漏检新形态或高度改写过的注入内容，判决为 `clean` 仅表示"覆盖范围内未检出"。 <br>
Mitigation: 不把 `clean` 当作安全保证；对高价值内容辅以人工复核，并关注后续版本更新。 <br>

Risk: skill 会读取用户指定的文件与目录以完成检测，若用户指向敏感路径，可能暴露内容范围。 <br>
Mitigation: 内置防护——拒绝系统目录、拒绝读取 `.env`/私钥/凭据类敏感文件（只报存在）、不跟随符号链接、只读打开、默认不写任何文件。 <br>

Risk: 检测引擎以本地脚本方式执行，运行权限等同于当前用户。 <br>
Mitigation: 引擎为纯标准库实现，无网络导入、无动态执行（自我核查可通过 `--self-check` 复核）；建议在可信环境或沙箱中运行。 <br>

Risk: 输出中若完整复述被检内容，可能把恶意载荷带进聊天记录或日志。 <br>
Mitigation: 输出统一脱敏——证据串长度上限、密钥掩码、编码载荷不还原原文；建议宿主模型只做解释、不转述原文。 <br>

## Reference(s): <br>
- [源码仓库](https://github.com/a9320/tianxi-ai-content-guard) <br>
- [检测规则说明](references/rules.md) <br>
- [安全说明与边界](references/security-notes.md) <br>

## Skill Output: <br>
**Output Type(s):** [Text, Guidance, Code, Configuration] <br>
**Output Format:** [Markdown 报告 + JSON 信封（verdict / counts / findings / next_actions）；命令行支持 `--text` / `--file` / `--dir` / `--decode` / `--self-check`] <br>
**Output Parameters:** [1D] <br>
**Other Properties Related to Output:** [全程本地执行，不发起任何网络请求；默认不写文件，仅在命中较多或用户指定时写出脱敏报告。] <br>

## Skill Version(s): <br>
1.2.15 <br>

## Ethical Considerations: <br>
本 skill 用于防御性内容审计，不生成攻击内容、不执行被检内容、不提供绕过手段。检测结论为概率性提示而非安全认证，用户应自行评估是否适用于其环境，并在依赖输出前复核关键结论。使用前请阅读 skill 描述中的输入方式与限制说明。 <br>