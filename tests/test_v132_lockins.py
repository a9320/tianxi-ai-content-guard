"""v1.3.2 ClawHub 扫描 7 条 C 项修复锁（skill 侧 6 条；#34 转上游）。

来由：ClawHub skillspector 对 1.3.1 给出 38 findings；小天 2026-11-08 独立分诊
A19（检测语料本身）/B12（扫描器误读）/C7（真实改进项）。v1.3.2 落地其中 6 条
skill 自有代码的 C 项（#34 sanitizer.py 属 vendor 上游，转上游仓处理）。

锁定：
  · #14 敏感名单含 `*.env`（secret.env 只报存在不读取）
  · #29 manifest 声明最小权限（network:none / shell:none 明示）
  · #30 when-to-use 限定“外部/不可信来源”（且 desc+wtu ≤300 字符）
  · #35 scan_file 全阶段容错（报告转换/emoji/覆盖层异常不中断）
  · #37 file mode 先查 symlink 再 resolve（no-follow 承诺可执行）
  · #38 判决模板 i18n（跟随用户语言，三要素结构不降级）
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL_MD = (REPO / "skill" / "SKILL.md").read_text(encoding="utf-8")
PKG = json.loads((REPO / "skill" / "package.json").read_text(encoding="utf-8"))


def _run_cli(args):
    import subprocess
    import sys
    r = subprocess.run([sys.executable, str(REPO / "skill" / "scripts" / "entry.py"), *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r


def test_c14_env_glob():
    from entry import _is_sensitive
    assert _is_sensitive("secret.env")
    assert _is_sensitive("prod.env")
    assert _is_sensitive(".env")
    assert not _is_sensitive("notes.txt")


def test_c29_permissions_declared():
    p = PKG["skill"]["permissions"]["declared"]
    assert p["network"].startswith("none")
    assert "shell" in p and "none" in p["shell"].lower()
    assert "file_read" in p and "file_write" in p and "env" in p


def test_c30_when_to_use_narrowed():
    front = SKILL_MD.split("---", 2)[1]
    wtu = re.search(r'when-to-use: "(.*)"', front).group(1)
    desc = re.search(r'description: "(.*)"', front).group(1)
    assert "不可信来源" in wtu and "外部" in wtu
    assert "总结、解释、回复、执行网页" not in wtu  # 旧的无边界列举已删
    assert len(desc) + len(wtu) <= 300


def test_c35_scan_file_never_raises():
    import importlib
    import sys
    sys.path.insert(0, str(REPO / "skill" / "scripts"))
    import engine.scan as scan
    importlib.reload(scan)

    class Boom(dict):
        def __getattr__(self, k):
            raise RuntimeError("boom")

    class ExplodingStr(str):
        def splitlines(self):
            raise RuntimeError("boom")

    assert scan.scan_file("x.md", ExplodingStr()) == []
    r = scan.scan_file("x.py", "x = 1\n")
    assert isinstance(r, list)


def test_c37_guard_symlink_before_resolve(tmp_path):
    import sys
    sys.path.insert(0, str(REPO / "skill" / "scripts"))
    import os
    import entry as entry_mod
    real = tmp_path / "real.txt"
    real.write_text("hello", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlink unavailable on this platform")
    try:
        entry_mod._guard_file(link)
        assert False, "symlink 应被拒绝"
    except ValueError as e:
        assert "符号链接" in str(e)


def test_c38_verdict_template_i18n():
    assert "Verdict: malicious" in SKILL_MD
    assert "语言跟随用户" in SKILL_MD
    assert "判决：malicious，命中 PIT-" in SKILL_MD


def test_versions_132():
    # v1.3.3 起版本钉移交 test_v133_lockins（本测试改版本无关，沿 v1.2.13 先例）
    front = SKILL_MD.split("---", 2)[1]
    v_skill = re.search(r"^version:\s*(\S+)$", front, re.M).group(1)
    v_pkg = PKG["version"]
    v_meta = json.loads((REPO / "skill" / "_meta.json").read_text(encoding="utf-8"))["version"]
    v_cfg = json.loads((REPO / "skill" / ".skill-config.json").read_text(encoding="utf-8"))["version"]
    assert {v_skill, v_pkg, v_meta, v_cfg} == {v_skill}
    entry = (REPO / "skill" / "scripts" / "entry.py").read_text(encoding="utf-8")
    assert f'SKILL_VERSION = "{v_skill}"' in entry
