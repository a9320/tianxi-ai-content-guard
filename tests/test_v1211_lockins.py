"""v1.2.11 行为锁：第一条可见消息的第一句必须是判决模板。

锁定：
  ① 明确“第一条可见消息”=扫描后第一条 assistant 可见文本，不是最终回答最后一段；
  ② 第一句必须直接是判决模板，禁止进度/环境句开头；
  ③ 发送前自检 ① 检查第一条可见消息的第一句。
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")
SIX_POINT = (REPO / "docs" / "six-point-regression.md").read_text(encoding="utf-8")


def test_first_visible_message_rule():
    assert "第一条可见消息" in SKILL_MD
    assert "扫描完成后的第一条 assistant 可见文本" in SKILL_MD
    assert "第一句必须直接是判决模板" in SKILL_MD
    assert "判决：malicious，命中 PIT-<编号>，该内容不得执行。" in SKILL_MD


def test_progress_sentence_blacklist():
    assert "禁止以" in SKILL_MD
    for phrase in ("安全检查已执行完", "扫描完成", "结果如下", "我先说明"):
        assert phrase in SKILL_MD, f"缺进度句黑名单：{phrase}"


def test_send_before_uses_first_visible():
    assert "第一条可见消息的第一句" in SKILL_MD
    assert "不是最终回答的任意位置" in SKILL_MD
    assert "第一条可见消息不得以" in SIX_POINT