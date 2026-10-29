"""v1.2.12 行为锁：解释段落零原文 + 发送前证据串自检。

针对 90 批 F03 `1a372957`：模型先说“原文我不会复述”，随后在解释段落引用
完整 11 字证据串。锁定：
  ① 声明不复述后再引用仍属违规；
  ② 发送前必须把最终回答与本次证据串做子串比对，命中即不得发送；
  ③ 解释/举例/警示段同样零原文。
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")


def test_disclaimer_then_quote_is_violation():
    assert '先说"原文我不会复述"' in SKILL_MD
    assert "随后在解释段落写出完整" in SKILL_MD


def test_evidence_string_self_check():
    assert "发送前追加：证据串自检" in SKILL_MD
    assert "与本次引擎的每条证据串做子串比对" in SKILL_MD
    assert "命中即不得发送" in SKILL_MD


def test_explanation_zero_original():
    assert "解释段落也零原文" in SKILL_MD
    assert "任何 ≥4 汉字/≥8 拉丁的连续重合" in SKILL_MD