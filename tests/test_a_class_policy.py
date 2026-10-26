"""A 类判据单一事实源一致性（批 1 审计 v2）。

锁死：benchmark/a_class_policy.json、docs/trigger-benchmark.md、skill/SKILL.md
三处引用同一组阈值；邮箱/URL/域名/IP/电话永不排除。
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICY = json.loads((REPO / "benchmark" / "a_class_policy.json").read_text(encoding="utf-8"))
DOC = (REPO / "docs" / "trigger-benchmark.md").read_text(encoding="utf-8")
SKILL = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")


def test_policy_keys_and_values():
    for key in ("min_cjk_run", "min_latin_run", "min_b64_len", "coverage_threshold",
                "coverage_min_cjk_run", "coverage_min_latin_run",
                "long_run_cjk", "long_run_latin"):
        assert key in POLICY, f"策略缺字段：{key}"
    assert POLICY["min_cjk_run"] == 4
    assert POLICY["min_latin_run"] == 8
    assert POLICY["min_b64_len"] == 20
    assert POLICY["coverage_threshold"] == 0.5
    assert POLICY["coverage_min_cjk_run"] == 8
    assert POLICY["coverage_min_latin_run"] == 16
    assert POLICY["long_run_cjk"] == 12
    assert POLICY["long_run_latin"] == 24


def test_doc_matches_policy():
    assert "a_class_policy.json" in DOC
    assert "中文 ≥4 字、拉丁 ≥8 字符" in DOC
    assert "≥20 字符" in DOC
    assert "覆盖率 ≥50%" in DOC
    assert "≥8 或拉丁 ≥16" in DOC
    assert "≥12 或拉丁 ≥24" in DOC
    assert "邮箱/URL/域名/IP/电话**绝不排除**" in DOC


def test_skill_matches_policy():
    assert "≥4 个汉字" in SKILL and "≥8 个拉丁字符" in SKILL
    assert "≥20 字符" in SKILL
    assert "含数字" in SKILL
    assert "B 类观察" in SKILL


def test_never_exclude_evidence():
    assert set(POLICY["never_exclude"]) >= {"email", "url", "domain", "ip", "phone"}