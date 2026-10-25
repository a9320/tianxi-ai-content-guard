# 设计决策（M1″ 定稿，2026-10-25）

依据：模型侧取证结论（宿主=DeepSeek-Flash 非推理快模型）+ 平台规范。改动需在此追加记录。

## 判决定谳三条（架构宪法）

1. **判决权归引擎。** 脚本出 verdict/counts/去重/脱敏，模型只解释措辞。输出带 `verdict_source:"engine"`；模型不得将 malicious 软化为 clean（记 `model_disagreement:true` 不改判）；模型拒答时确定性报告照出（`model_explanation:"unavailable"`）。
2. **三层输出信封。** 聊天只回 envelope.json（≤8k：verdict+counts+top5-10+报告路径+limits）；完整 findings 落 report.jsonl（一行一条，分页 ≤20k/页）；summary.md（≤2k 字）给人看。counts 由脚本算，summary 首尾各出现一次。
3. **注入防御五层自力。** 脚本预扫描（模型不看被检原文）→ `<untrusted_content>` 围栏（必须看原文时）→ `allowed-tools` 白名单（Read/Grep/Glob+固定参扫描脚本）→ 检测/解释两段式 → 输出 schema 校验。红队发布门槛：危险工具调用 0 / 原文泄露 0 / 判决劫持 0。

## 引擎模块（并入选项 A 重构，在 arcanum-spark 源头做）

| 模块 | 要点 |
|---|---|
| 特征外置 | 恶意特征串抽到 rules JSON，代码只加载匹配；**中英双语**（中文变体 confidence 降档起步，实弹确认后升级） |
| 四值判决 | malicious / suspicious / clean / **inconclusive**（工具失败/内容过大/不可解码）+ `coverage` 对象（bytes/files/truncated/limits）——"零命中≠安全"schema 化 |
| 脚本预脱敏 | 四档（none/summary/masked/full），默认 summary：隐形字符→`U+200B × 3` 记法；base64→前8+后8≤40；注入语句→类型+长度+SHA256 前8+≤40 字符片段；密钥→前4+****+后4。聊天 ≤120 字符；full 仅本地文件且用户明确同意 |
| 提及≠指令判定表 | 五信号打分进引擎：位置/对象/动词/结果/上下文（N-06 误报治律的代码化） |
| 解码帽 | base64 剥离 ≤3 层、输入 ≤64KB、解码输出 ≤256KB |
| 扫描防护 8 条 | realpath+系统目录拒绝（relative_to）/符号链接与 junction 不跟随/敏感文件只报存在/上限（5000 文件·200MB·深度 20·单文件 2MB·30s）/只读/二进制跳过/输出脱敏/PermissionError 优雅 |

## entry.py 契约

- 输入：`--text` / `--file`（`-`=stdin）/ `--dir` / `--mode config`（AI 配置审计专家入口）；stdin 宽容解析五形态（params.input/input/text/content/prompt/裸文本）；长文本不走 argv（Windows 32767 上限）。
- 编码三件套：stdout/stderr reconfigure UTF-8 errors=replace；stdin 读 buffer 按链解；文件显式编码。
- 输出：envelope+report.jsonl+summary.md 三件套；`--self-check` 打印网络/写盘/动态执行边界；`--out` 仅用户要求时写。
- 退出码：0 成功 / 1 `--fail-on` 命中 / 2 参数错误 / 3 运行时错误；输入 schema 严校验+结构化错误（`ok:false+error_code+hint`），模型重试 ≤1。
- **不钉模型**（frontmatter `model` 缺省；catalog 校验失败=激活报错）。
- 报告记录 `skill_version` + model key + 日期（模型漂移探测；Flash 系 58 天 3 更无通知）。

## 明确不做

完整 findings 塞聊天 / 模型读原文+exec 权限并存 / 纯英文 description / 承诺零误报 / fork 当沙箱 / 把 200 字符当平台阈值 / 未实测把 auto 写进 model 字段 / 依赖平台拦截注入 / 单次运行判断触发率。
