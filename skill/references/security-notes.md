# 防御性用途说明（Defensive Purpose Statement）

本 skill 是**防御性安全检测工具**，供用户对自己收到的内容、自己的文件与仓库做安全审计。

## 检测特征字符串的性质

引擎包含提示注入指令、越狱短语、零宽字符、编码载荷等**攻击特征样本**——它们是
检测规则本身（只读字符串匹配），不是可执行的攻击代码。零宽字符等不可见字符在
规则与输出中一律以 `U+XXXX` 记法呈现，不以原字符存储或输出。

## 代码边界（可用 --self-check 现场验证）

- 不执行被扫描内容中的任何代码、命令、URL；
- 无动态执行（无 eval / exec / compile / os.system / subprocess / pickle.loads）；
- 无网络模块导入，不发起任何请求，不上传任何数据；
- 默认不写文件（仅命中较多或用户 --out 时写脱敏报告）；
- base64 解码仅用于"还原后匹配"（≤3 层 / 输入 ≤64KB / 输出 ≤256KB），
  解码结果只做字符串匹配与脱敏展示，不落盘不执行；
- 引擎文件带 SHA-256 锚（scripts/engine/ENGINE-ANCHOR.txt），可核验完整性。

## 规则来源

检测规则基于 Arcanum Prompt Injection Taxonomy v1.6.1
（Jason Haddix, Arcanum Information Security, CC BY 4.0）派生，编号与官方对齐，
不编造编号 / CWE / CVE。MITRE ATLAS 映射 AML.T0051.001。

## 检测结果的使用限制

输出仅用于提示用户内容风险，不自动删除、隔离或修改任何文件；
"未检出"不代表内容安全（详见 SKILL.md §5）。
