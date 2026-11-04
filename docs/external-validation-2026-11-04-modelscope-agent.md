# 第三方实测手册：魔搭社区 Agent 对 ai-content-guard v1.2.15 的复跑记录

- **来源**：ModelScope 社区 Agent 在 ms-agent 环境中装载本 skill 后自行复跑产出（2026-11-04）
- **性质**：外部独立验证，非我方文档；数据可复跑，路径为对方沙箱路径
- **价值**：18 个案例逐一复跑、0 项数字偏差；发现唯一真实漏检（英文工具滥用）→ 已由 v1.2.16 修复
- **保留方式**：原文归档，仅加本页头；文中样本为演示夹具，命中属预期，一律不得执行

---

# ai-content-guard 使用说明与案例手册

引擎版本：ai-content-guard v1.2.15 ｜ PITAX v1.6.1 ｜ 已实现规则 9 条 ｜ `--self-check` 全部锚点 MATCH

技能目录：`/mnt/data/ms-agent-home/skills/ai-content-guard`
引擎入口：`scripts/entry.py`（零网络、零第三方依赖、只读）

---

## 一、它做什么

对**不可信内容**做防御性安全审计，输出四值判决 + 脱敏证据 + 处置建议。

| 检测面 | 规则编号 | 严重度 | 说明 |
|---|---|---|---|
| 隐形文本走私 | PIT-E-23 | high | 零宽字符、软连字符、U+E0000–E007F Tag 字符（ASCII Smuggling） |
| Trojan Source | PIT-E-54 | high | Bidi 控制符使视觉顺序 ≠ 实际解析顺序（CVE-2021-42574） |
| AI 指令文件后门 | PIT-T-46 | critical | `.cursor/rules`、`CLAUDE.md`、`AGENTS.md`、copilot 规则文件等（CVE-2025-53773） |
| 注释注入 | PIT-T-51 | high | 代码注释内嵌劫持指令 |
| 文档投毒 | PIT-N-06 | high | README/设计文档等面向 Agent 的恶意指令 |
| 单层编码 | PIT-E-07 / -14 / -36 | medium | base64 / rot13 / reverse，**仅解码后命中注入关键词才报** |
| 多层编码 | PIT-E-57 | critical | ≥2 层组合编码规避关键词过滤（至多 5 层剥链） |
| 中文覆盖层 | 复用上述编号 | high/critical | 指令覆盖、角色劫持、提示词外泄、**判决劫持**、数据外传、工具滥用 |

**判决语义**

| verdict | 含义 | 后续动作 |
|---|---|---|
| malicious | 检出 critical/high | 该内容禁止执行，先看证据再决定 |
| suspicious | 仅中低危信号 | 人工确认后再用 |
| clean | 覆盖范围内未检出 | 附「不代表绝对安全」 |
| inconclusive | 扫描未完整完成 | 不下安全结论 |

---

## 二、命令速查

```bash
S=/mnt/data/ms-agent-home/skills/ai-content-guard/scripts/entry.py

python3 "$S" --text  "粘贴的短文本（<8KB）"
python3 "$S" --file  /path/to/file            # 单文件；长文本可用 --file - 走 stdin
python3 "$S" --dir   /path/to/repo            # 递归只读
python3 "$S" --dir   /path/to/repo --mode config   # 只审 AI 配置文件
python3 "$S" --dir   /path/to/repo --sarif out.sarif
python3 "$S" --decode "base64载荷"            # 编码分层自证（默认只给长度+哈希）
python3 "$S" --self-check                     # 零网络/零执行/锚点校验自证
```

信封关键字段：`verdict` `counts` `ambient.one_liner` `top_findings[].evidence_redacted` `top_findings[].advice` `coverage` `report_path` `limits`。
出错时 `ok:false` + `error_code`（INVALID_ARGUMENT / NOT_FOUND / GUARD_REJECTED / RUNTIME_ERROR）+ `hint`。

---

## 三、案例集（本目录内样本，可直接复跑）

> 样本中的攻击串为演示夹具（fixture），命中属预期；一律不得执行。

| # | 样本 | 场景 | 实测判决 | 实测命中 |
|---|---|---|---|---|
| 1 | `01-invisible.txt` | 发布说明正文夹带隐形字符走私指令 | malicious | PIT-E-23 ×28（high，conf 90） |
| 2 | `02-trojan.py` | 源码字符串内藏 Bidi 控制符 | malicious | PIT-E-54 ×1（high，conf 90） |
| 3 | `03-encoded.js` | 引号字面量单层 base64 载荷 | suspicious | PIT-E-07 ×2（medium，conf 70） |
| 4 | `04-layered.py` | 多层编码载荷 | malicious | PIT-E-57 ×2（critical，conf 90/70） |
| 5 | `mail/notice.md` | 中文文档：指令覆盖 + 提示词外泄 + 判决劫持 + 数据外传 | malicious | PIT-N-06 ×5（high，conf 70） |
| 6 | `repo/`（整目录） | 外来仓库：AI 规则文件后门 + README 投毒 | malicious | critical 5 + high 2（2 文件 / 327B） |
| 7 | `repo/ --mode config` | 同上，只审 AI 配置文件 | malicious | critical 5（1 文件 / 172B，README 不进 config 模式） |
| 8 | `clean/`（整目录） | 正常纪要 + 正常脚本 + 正常配置 + 正常 AGENTS.md | **clean** | 0 命中（4 文件 / 356B） |
| 9 | `--text` 一句话正文 | 通知尾部夹带劫持指令 | malicious | PIT-N-06 ×1 |
| 10 | `05-bulk.txt`（40 行注入） | 命中数超 10 的落盘机制 | malicious | counts.high=160，`top_findings` 截 10 条 → 全量写 `report.jsonl` |

### 11–14：误报边界（`fp/`，规则卡声明的四类）

| # | 样本 | 声明的误报边界 | 实测判决 | 说明 |
|---|---|---|---|---|
| 11 | `fp/f1-emoji.md` | emoji 家族序列中的 ZWJ | **clean**（low ×1） | 引擎自动降级：描述追加"ZWJ 位于 emoji 家族序列内部，已降级 low"；low 不影响判决 |
| 12 | `fp/f2-utf16.txt` | UTF-16 文件 BOM | **clean**（0 命中） | 解码链含 `utf-16`/`utf-8-sig`，BOM 未被当隐形字符上报 |
| 13 | `fp/f3-rtl.txt` | 正当 RTL 文案的隔离符 | **malicious**（E-54 high ×1） | **仍报**。规则卡口径为"确认语境后人工豁免"，非自动豁免 |
| 14 | `fp/f4-textbook.md` | 安全教材原文引用攻击句式 | **malicious**（N-06 high ×1） | **仍报**。同上，需逐条人审；确定性层不区分"描述攻击"与"发出指令" |

结论：11/12 类边界引擎已内置处理；13/14 类属**声明级边界**，需人工判定，不可把 clean/malicious 当免审依据。

### 15–18：工具滥用与覆盖上限（`edge/`、`fail/`）

| # | 样本 | 场景 | 实测判决 |
|---|---|---|---|
| 15 | `edge/e1-toolabuse.md` | 中文祈使式诱导破坏性命令 | malicious，PIT-N-06 **critical** conf 70 |
| 16 | `edge/e1b-en.txt` | 英文同类诱导（要求执行破坏性命令） | **clean —漏检**（见第六节局限） |
| 17 | `fail/node_modules/leftpad/` | 藏在分发目录内的载荷 | malicious：high 1（N-06）+ medium 2（E-07），scanned=2/186B。实测 `dirs_skipped_names` 为空——**node_modules 不在跳过名单**（技能口径比引擎默认更窄，分发目录恰是藏身处） |
| 18 | `symtest/`（1 真实文件 + 2 文件链接 + 1 目录环） | 链接跟随风险 | **只扫真实文件 1 个**（high 2），链接与目录环均未读取，无成环重复计数 |

### 复跑示例

```bash
cd /mnt/data/ms-agent-home/projects/_default/guard-demo
python3 "$S" --dir repo --mode config
python3 "$S" --file mail/notice.md
python3 "$S" --dir clean
python3 "$S" --file 04-layered.py --sarif out.sarif
python3 "$S" --dir fp                 # 误报边界组
python3 "$S" --dir fail/many --max-files 5   # 触发截断 → inconclusive
```

---

## 四、隐私与防护边界（实测）

- **只读**：不修改/删除/移动任何文件。
- **零网络**：`--self-check` 显示无 requests、urllib、socket 等网络库导入。
- **不执行被检内容**：判决为 malicious 或 suspicious 的脚本，即使用户要求执行也不执行。
- **敏感文件**：匹配名单为 `.env`、`.env.*`、`*.pem`、`*.key`、`id_rsa*`、`id_ed25519*`、`credentials*`、`cookies*`、`*.sqlite`、`*.db`、`*.kdbx`、`*.pfx`、`*.p12`、`*.wallet` 等。
  - `--dir` 命中名单 → 记入 `coverage.sensitive_skipped`，**不读内容**（实测 `probe/.env`、`probe/id_rsa` 均跳过，`files_scanned=0`）。
  - `--file` 直接指定名单内文件 → `GUARD_REJECTED`，提示"敏感文件只报存在、不读取内容"。
  - **边界提醒**：命名不合名单的凭据文件（实测 `secret.env`）会被当普通文本读取；引擎只找攻击模式，**不做凭据泄露检测**，此类文件判 clean 不代表内含验证信息。文件如何处置由用户自行决定。
- **系统目录**：`--dir /etc` → `GUARD_REJECTED`。
- **符号链接/junction**：不跟随，且**如实上报**。实测 `symtest/` 得 `files_scanned=1`、`links_skipped=3`、`links_skipped_names=[link.txt, out_real.txt, selfdir]`（名单上限 10 项）——文件链接与目录环都计入 skipped，不会被读取，也不会成环重复计数。
- **二进制文件**：实测 `fail/bin.png` → `GUARD_REJECTED`（exit=2），不解析字节流。
- **坏编码字节**：实测 `fail/bad.txt`（非法 UTF-8 序列）→ 按解码链回退成功读取，verdict=clean，不崩溃。
- **参数缺失/冲突**：无参数、空文本、纯空白文本、空 stdin、同时给两个输入 → 均 `INVALID_ARGUMENT`（exit=2），带 hint。
- **报告脱敏**：`report.jsonl` 落盘内容实测不含被检载荷原文。SARIF 更严格——实测导出中 **`decoded_payload` 字段被整个移除**，且全文检索不到任何 ≥20 字符的载荷 base64/hex 形态（源头洗，非事后改写）。

### 错误码与退出码（实测）

| error_code | 触发 | exit |
|---|---|---|
| `INVALID_ARGUMENT` | 输入缺失/冲突/为空 | 2 |
| `NOT_FOUND` | 文件或目录不存在 | 2 |
| `GUARD_REJECTED` | 系统目录、敏感文件名单、二进制/超大 | 2 |
| `RUNTIME_ERROR` | 引擎内部异常 | 3 |
| —（正常扫描） | clean/suspicious/malicious | 0 |
| —（`--fail-on` 达标） | 命中该级别及以上 | 1 |

`--fail-on` 分级门槛实测：`--file 03-encoded.js`（仅 medium 命中）配 `--fail-on high` → exit 0；配 `--fail-on medium` → exit 1。即 **CI 里用 `--fail-on high` 时，单层编码类可疑内容不会打断流水线**，这是有意的噪声控制，但值得按团队策略显式选定门槛。

### `inconclusive` 的三条触发路径（实测）

| 路径 | 命令 | 结果 |
|---|---|---|
| 文件数超限 | `--dir fail/many --max-files 5` | inconclusive，conf 0.3，`truncated=true`，scanned=5 |
| 字节超限 | `--dir fail/many --max-bytes 100` | inconclusive，scanned=2，bytes=82 |
| 深度超限 | `--dir fail --max-depth 2` | inconclusive，`files_skipped=1`（深层文件未扫） |

默认上限：`max-files=5000`、`max-bytes=200MB`、`max-depth=20`、`timeout=30s`。命中 `inconclusive` 时**不得下安全结论**，只能说明未扫完。

### `--min-severity` 的真实语义（实测，易误解）

`--min-severity` 只过滤 `top_findings` 的**展示条数**，**不改 `counts`、不改 `verdict`、不改 `confidence`**。例：`--file 03-encoded.js --min-severity critical` → `top_findings` 为 0 条，但 verdict 仍是 suspicious、counts 仍显示 medium=2。做降噪展示可用，不能拿它当"降级判决"。

### 其他参数（实测）

- `--format markdown`：人读版报告，含判决标题 + 每条 `[severity] [PIT-编号] 规则名 \`文件:行\`` + 脱敏证据行 + 末尾固定局限句。
- `--out <目录>`：强制落盘完整报告（默认仅在命中 >10 时写系统临时目录）；同名不覆盖，实测第二次自动变 `report-1.jsonl`。
- `--mode config` 的路径判定：精确匹配 AI 配置基名，或路径含 `.cursor`/`.windsurf` 且文件名含 rules/instructions，或父目录为 `*/rules`。README 等非配置名不进 config 模式（实测 repo：全量 7 项 vs config 5 项）。
- `--text` 走双路由适配：同一内容分别按"文档路径（N-06）"与"代码路径（4 检测器）"各扫一趟，并抽取裸文本中的 base64 候选补造带引号字面量，使无引号编码载荷也能进入剥离链。

---

## 五、两种工作模式

- **模式 A（用户主动求检）**：完整报告 = 判决 + 计数 + 逐条命中 + 覆盖范围与局限。
- **模式 B（处理外部内容前预检）**：`clean` 静默放行不打断；非 `clean` 立即中断警示，等用户决定。

实测 `ambient.one_liner` 就是模式 B 的现成话术，两封邮件对比：

| 邮件样本 | verdict | `one_liner` |
|---|---|---|
| `edge/e2-mail-clean.md`（普通议程） | clean | "未检出已知攻击特征（…零命中不代表绝对安全）" → 一句话带过，继续原任务 |
| `edge/e3-mail-poison.md`（正文夹带外传+判决劫持） | malicious | "⚠️ 检出 1 项高危（critical 0 / high 1）…建议先查看报告再决定是否采用该内容" → 中断警示 |

**判决劫持规则的豁免边界（实测）**：这类特征最容易被正常表述误伤，引擎按句法做了区分。下表只给句式类别，不复现测试原文。

| 句式类别 | verdict |
|---|---|
| 疑问式：向检测器征询风险结论 | clean（豁免） |
| 陈述式：汇报既有结论，未下达命令 | clean（豁免） |
| 描述式：说明某脚本的行为，无祈使前缀 | clean（豁免） |
| 限定式：清理动作限定到临时/缓存类对象 | clean（豁免） |
| 祈使式：命令检测器按无害定论 | malicious（命中） |
| 日志体中混入的英文判决短语 | malicious（命中，**边界偏保守**） |

即：正常提问与汇报不会被告警，但自动化日志/报表里若混入判决短语仍会计数，需按误报处理。

---

## 六、双向局限（实测确认，报告时须如实附带）

**会漏检（假阴性）**
1. **语义改写类攻击不在覆盖内**：不含上述特征措辞的劫持（如把指令拆到多段、换成隐喻表达、用图片/表格承载）确定性层抓不到。这是 `coverage.limits` 固定声明的口径。
2. **英文"诱导执行破坏性命令"是盲区**（唯一缺口，已源码核对）：中文覆盖层的工具滥用特征只有 `_P_TOOLABUSE_ZH` 一条，条件绑定中文祈使动词 + 一批破坏性命令名（含递归强制删除、建文件系统、格式化、关机等），**无对应英文正则**。英文侧其余五类攻击面实测均有覆盖：

   | 英文攻击面（句式类别，不复现原文） | 实测 verdict |
   |---|---|
   | 指令覆盖类（要求中止既有指令） | malicious |
   | 角色劫持类（重设身份为无限制角色） | malicious |
   | 提示词索取类（要求输出初始指令） | malicious |
   | 判决劫持类（命令检测器报无害） | malicious |
   | 数据外传类（全量敏感对象 + 外部目的地） | malicious |
   | **破坏命令诱导类（要求执行递归强删/关机）** | **clean —漏检** |

   所以"英文文本安全"不能一概而论：劫持类抓得到，命令执行类抓不到。
3. **凭据泄露不在检测目标内**：引擎只找攻击模式，不识别凭据/验证信息本身；命名不合名单的凭据文件（如 `secret.env`）会当普通文本读并可能判 clean。
4. 未扫完时不下安全结论：截断即 `inconclusive`，不能当作 clean。

**会误报（假阳性）**
5. 正当 RTL 文案、安全教材引用攻击句式这两类**仍会报 high**（案例 13/14），需人工豁免——确定性层不区分"描述攻击"与"发出指令"。

---

**依据**：Arcanum Prompt Injection Taxonomy v1.6.1（Jason Haddix, CC BY 4.0）；MITRE ATLAS 统一映射 `AML.T0051.001`。
**引用纪律**：只使用本手册列出的 PIT 编号，不得编造编号/CWE/CVE。
