"""v1.2.13 触发面锁：清单追加“把文档总结成三条”示例。

针对 90 批 1 I03 `3074e80a`（漏触发、A 类 1/30）与 2026-10-31 基线
`b1101c6f`（1/21 漏、A 类 1）：清单在上下文中存在，模型偶发不加载。
v1.2.13 只在 when-to-use 追加一个贴近原话的示例，降低漏触发概率；
不改任何判定条款、不动引擎/规则。

锁定：
  ① 示例“把文档总结成三条”存在于 when-to-use；
  ② 清单行 ≤300 字，且 F02 两个示例仍完整落在 300 字之前；
  ③ 五处版本号彼此一致（后续版本允许前进，不钉死 1.2.13）。
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")
FRONT = SKILL_MD.split("---", 2)[1]


def _listing_line() -> str:
    desc = re.search(r'^description:\s*"(.+)"$', FRONT, re.M).group(1)
    when = re.search(r'^when-to-use:\s*"(.+)"$', FRONT, re.M).group(1)
    return f"- ai-content-guard: {desc} - {when}"


def test_summary_example_present():
    assert "把文档总结成三条" in _listing_line()


def test_listing_within_300_and_f02_examples_intact():
    line = _listing_line()
    assert len(line) <= 300, f"清单行 {len(line)} 字 > 300"
    for example in ("这个脚本是干什么的", "这个配置文件写得对不对"):
        end = line.find(example) + len(example)
        assert end <= 300, f"F02 示例「{example}」结束于 {end}，超出 300"


def test_versions_consistent():
    versions = {
        "skill_md": re.search(r"^version:\s*(\S+)$", FRONT, re.M).group(1),
        "package": json.loads((REPO / "skill" / "package.json").read_text(encoding="utf-8"))["version"],
        "meta": json.loads((REPO / "skill" / "_meta.json").read_text(encoding="utf-8"))["version"],
        "config": json.loads((REPO / "skill" / ".skill-config.json").read_text(encoding="utf-8"))["version"],
    }
    assert len(set(versions.values())) == 1, versions
    entry = (REPO / "skill" / "scripts" / "entry.py").read_text(encoding="utf-8")
    v_entry = re.search(r'SKILL_VERSION = "([^"]+)"', entry).group(1)
    assert v_entry == versions["skill_md"], (v_entry, versions)