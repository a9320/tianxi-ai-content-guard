"""v1.2.10 行为锁：六点混合修补的三处文案（引擎/规则零改动）。

锁定：
  ① 清单增加安装/翻译/仓库 triage 三个显式例子，全部落在 300 字内；
  ② 正文注入后第一动作必须是 entry.py；同轮已发 Read 且正文未到则停读等正文；
  ③ 第 6 节发送前 3 项自检（第一句/加载前引用/载荷段）。
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")
EXAMPLES = (
    "这个脚本是干什么的",
    "这个配置文件写得对不对",
    "按 README 安装仓库",
    "翻译消息文件",
    "整理仓库问题清单",
)


def test_listing_examples_and_budget():
    front = SKILL_MD.split("---", 2)[1]
    desc = re.search(r'^description:\s*"(.+)"$', front, re.M).group(1)
    when = re.search(r'^when-to-use:\s*"(.+)"$', front, re.M).group(1)
    line = f"- ai-content-guard: {desc} - {when}"
    assert len(line) <= 300, f"清单行 {len(line)} 字 > 300"
    for example in EXAMPLES:
        assert example in line, f"缺显式例子：{example}"
        end = line.find(example) + len(example)
        assert end <= 300, f"例子「{example}」结束于 {end}，超出 300"


def test_post_injection_first_action():
    assert "正文注入后的第一动作必须是 `entry.py`" in SKILL_MD
    assert "不要补读" in SKILL_MD


def test_same_round_skill_read_boundary():
    assert "同一轮已经发出 `Read`" in SKILL_MD
    assert "等正文到达后直接扫描" in SKILL_MD


def test_send_before_three_checks():
    assert "发送前 3 项自检" in SKILL_MD
    assert "是否同时含" in SKILL_MD and "判决词" in SKILL_MD
    assert "第一条可见消息的第一句" in SKILL_MD
    assert "扫描前/加载前是否引用" in SKILL_MD and "原文片段" in SKILL_MD
    assert "载荷段是否只给类型+长度+编号+风险结论" in SKILL_MD