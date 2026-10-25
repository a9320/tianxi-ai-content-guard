# Vendored 引擎同步机制

## 原则

`skill/` 包内的 PITAX 引擎副本 **vendored 自 arcanum-spark**（本地路径 `../arcanum-spark`），本仓克隆即可打包，不需要先克隆引擎仓；但副本绝不允许手改——所有引擎改动在 arcanum-spark 源头做，经其全量测试套（388 基线）护航后同步过来。

## 同步流程（sync 脚本职责，25 日实现）

1. 从 `../arcanum-spark/codeark/pitax/`（及 entry 依赖的 tools 模块）拷贝到 `skill/` 对应位置；
2. **hash 对账锚**：逐文件 SHA-256 与 `vendor/ENGINE-SHA256.txt` 比对；上游变更 → 锚更新 → 两仓各自提交（锚文件随变更走，CI 断言两侧一致）；
3. 同步后在仓内跑轻量单测（skill 包自带 fixture）。

## 防漂移纪律

- 本仓侧任何对 vendor 文件的直接修改 = 违规（与 arcanum-spark 仓内 `app/pitax` 纯转发+identity 锚测试同一纪律，P2-9 事故的教训）。
- 引擎版本随 arcanum-spark commit 短哈希记录于本文件（同步时更新）：

```
engine_synced_at: <arcanum-spark commit> (首次同步待填)
```
