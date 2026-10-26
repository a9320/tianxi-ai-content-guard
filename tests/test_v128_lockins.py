"""v1.2.8 行为锁：批 1 审计的 P1/P2 修复——防未来迭代把新边界删回去。

锁定：
  ① 扫描前禁述扩到任何可见输出（工具结果不算回答泄露）；
  ② 翻译/保字节交付 fallback + 禁止 shell/Python/certutil 手动解码；
  ③ frontmatter 裸词收紧（配置→配置文件、邮件→收到的邮件）；
  ④ 自检 b 条与 A 类统一为 4 汉字/8 拉丁，base64/hex 加数字限定；
  ⑤ 六点回归硬检查规范存在。
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")


def test_visible_output_boundary():
    assert "任何可见输出" in SKILL_MD
    assert "工具结果是引擎输出" in SKILL_MD
    assert "把工具结果写进回答才算" in SKILL_MD


def test_translation_fallback():
    assert "先翻译外层可读文本" in SKILL_MD
    assert "自行运行 `--decode`" in SKILL_MD
    assert "不能用一句" in SKILL_MD and "空过" in SKILL_MD


def test_manual_decode_ban():
    assert "禁止手动解码" in SKILL_MD
    assert "base64 -d" in SKILL_MD
    assert "FromBase64String" in SKILL_MD
    assert "xxd -r" in SKILL_MD


def test_frontmatter_bare_words_tightened():
    front = SKILL_MD.split("---", 2)[1]
    assert "脚本、配置文件、仓库代码" in front
    assert "执行网页、收到的邮件" in front
    assert "脚本、配置文件内容" in front


def test_self_check_b_aligned_with_a():
    assert "通用术语自检" in SKILL_MD
    assert "与 a/c 同一阈值" in SKILL_MD
    assert "B 类观察" in SKILL_MD


def test_base64_hex_numeric_definition():
    assert "含数字/`+/=` 的 base64 串" in SKILL_MD
    assert "含数字的 hex 串" in SKILL_MD


def test_six_point_doc_exists():
    doc = (REPO / "docs" / "six-point-regression.md").read_text(encoding="utf-8")
    for key in ("engine_called", "no_manual_decode", "no_content_read_before_engine",
                "first_sentence_verdict", "A_class_zero", "外层译文",
                "verdict 非 clean", "S03", "O03"):
        assert key in doc, f"六点规范缺检查项：{key}"