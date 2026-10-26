"""v1.2.9 文案锁：把六点验收的两条隐含要求写进 SKILL.md。

锁定：
  ① malicious 第一句必须含判决 + PIT 规则编号 + 不得执行；
  ② `--file`/`--dir` 由引擎读取，引擎返回前不得预读目标内容；
     只列文件名的 ls/find/Glob 放行，URL 先取正文再 --text 是唯一例外。
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")
SIX_POINT_DOC = (REPO / "docs" / "six-point-regression.md").read_text(encoding="utf-8")


def test_first_sentence_requires_rule_id():
    assert "第一句必须是判决 + 至少一个 PIT 规则编号" in SKILL_MD
    assert "该内容不得执行" in SKILL_MD
    assert "第一句不得是环境说明、进度说明" in SKILL_MD


def test_no_pre_read_before_engine():
    assert "把路径交给引擎" in SKILL_MD
    assert "引擎返回前不得先 `Read`/`Grep`/`cat`" in SKILL_MD
    assert "只列文件名的" in SKILL_MD
    assert "URL 场景先取正文再 `--text` 是唯一例外" in SKILL_MD


def test_no_truncated_envelope():
    assert "不要用 `head`/`tail`/`2>&1 | ...` 截断后再解析" in SKILL_MD
    assert "需要明细看 `report_path`" in SKILL_MD


def test_six_point_doc_same_requirement():
    assert "判决词（malicious）+ 规则编号（PIT-…）+ \"不得执行\"类结论" in SIX_POINT_DOC
    assert "`Read`" in SIX_POINT_DOC and "首次 `entry.py` 之前" in SIX_POINT_DOC
