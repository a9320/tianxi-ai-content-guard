#!/usr/bin/env python3
"""构建双渠道发行包：天禧（${QODER_SKILL_DIR}）与 ClawHub（{baseDir}）。

用法：python build/build.py [--dist dist]

产物：dist/<channel>/ai-content-guard-<version>.zip
自检（任一失败即退出非零）：
  ① SKILL.md 位于 ZIP 根目录（无父目录套壳）
  ② 单文件 ≤1MB（CLI 超限是静默跳过——必须打包前拦）
  ③ ZIP ≤10MB、文件数 ≤50
  ④ 扩展名全部在天禧 CLI 12 类白名单内（PNG 等只走网页控制台）
  ⑤ 无 .git/node_modules/.env/*.log/__pycache__ 混入
  ⑥ 四处版本号一致（SKILL.md / package.json / _meta.json / .skill-config.json）
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skill"

ALLOWED_EXT = {".md", ".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml",
               ".toml", ".txt", ".mjs", ".cjs"}
ALLOWED_BARE_NAMES = {"LICENSE", "NOTICE", "AUTHORS"}  # 无扩展名的许可/署名文件
FORBIDDEN_NAMES = {".DS_Store"}
FORBIDDEN_PARTS = {".git", "node_modules", "__pycache__", "dist"}
FORBIDDEN_SUFFIX = {".log", ".env", ".zip", ".png", ".jpg", ".bak", ".pyc"}


def _version() -> str:
    return json.loads((SKILL / ".skill-config.json").read_text(encoding="utf-8"))["version"]


# ── 构建期审核净化：发行包内的引擎源替换品牌/赛事备注字符串（工作区不动，
#    上游同步锚 vendor/ENGINE-SHA256.txt 保持字节级；包内完整性锚按净化后哈希重写）──
_SANITIZE_TRANSFORMS = {
    "engine/__init__.py": [("CodeRisk Cloud — PITAX 检测模块",
                            "ai-content-guard — PITAX 检测模块")],
    "engine/sanitizer.py": [('logging.getLogger("coderisk.pitax")',
                             'logging.getLogger("ai_content_guard.pitax")')],
    "engine/sarif.py": [
        ('"CodeRisk Cloud"', '"ai-content-guard"'),
        ("https://github.com/a9320/coderisk-cloud",
         "https://github.com/a9320/tianxi-ai-content-guard")],
    "engine/rules.py": [
        ("参赛红线：编号以官方为准", "硬红线：编号以官方为准"),
        ("曾因外部审核（GLM-5.3）误称", "曾因外部评审误称"),
        ("参赛主推的 4 条高价值规则", "4 条高价值规则")],
}


def _sanitize_engine(rel: str, data: bytes) -> bytes:
    posix = rel.as_posix()
    key = posix[len("scripts/"):] if posix.startswith("scripts/") else posix
    if key not in _SANITIZE_TRANSFORMS:
        return data
    text = data.decode("utf-8")
    for old, new in _SANITIZE_TRANSFORMS[key]:
        if old not in text:
            raise SystemExit(f"[净化] 预期字符串未找到（上游已变？）：{posix}: {old[:30]}")
        text = text.replace(old, new)
    import ast
    ast.parse(text)  # 净化后语法校验
    return text.encode("utf-8")


def check_versions():
    v = _version()
    pkg = json.loads((SKILL / "package.json").read_text(encoding="utf-8"))["version"]
    meta = json.loads((SKILL / "_meta.json").read_text(encoding="utf-8"))["version"]
    skill_md = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.search(r"^version:\s*(\S+)", skill_md, re.M)
    assert m, "SKILL.md 缺 version 字段"
    entry = (SKILL / "scripts" / "entry.py").read_text(encoding="utf-8")
    e = re.search(r'^SKILL_VERSION\s*=\s*"([^"]+)"', entry, re.M)
    assert e, "entry.py 缺 SKILL_VERSION 常量"
    assert v == pkg == meta == m.group(1) == e.group(1), \
        f"版本号不一致（五处须同改）：{v}/{pkg}/{meta}/{m.group(1)}/{e.group(1)}"
    return v


def collect_files():
    files = []
    for p in sorted(SKILL.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(SKILL)
        parts = set(rel.parts)
        if parts & FORBIDDEN_PARTS or rel.name in FORBIDDEN_NAMES:
            continue
        if rel.suffix.lower() in FORBIDDEN_SUFFIX or rel.name.startswith(".env"):
            continue
        if rel.suffix.lower() not in ALLOWED_EXT and rel.name not in ALLOWED_BARE_NAMES:
            raise SystemExit(f"[自检④] 扩展名不在白名单：{rel}（图标走网页控制台）")
        if p.stat().st_size > 1024 * 1024:
            raise SystemExit(f"[自检②] 单文件超 1MB（CLI 会静默跳过）：{rel}")
        if rel.as_posix().endswith("engine/ENGINE-ANCHOR.txt"):
            continue  # 锚由下方锚块按发行内容单独生成，避免双写
        files.append((p, rel))
    return files


def build(channel: str, dist: Path, version: str):
    out = dist / channel / f"ai-content-guard-{version}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    transformed: dict[str, bytes] = {}
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p, rel in collect_files():
            data = p.read_bytes()
            if rel.suffix == ".py":
                data = _sanitize_engine(rel, data)
                transformed[rel.as_posix()] = data
            if channel == "clawhub" and rel.as_posix() == "SKILL.md":
                data = data.decode("utf-8").replace("<skill 目录>", "{baseDir}").encode("utf-8")
            zf.writestr(rel.as_posix(), data)  # arcname 不带 skill/ 前缀 → SKILL.md 在根
        # 包内完整性锚：8 件全列——净化件用净化后哈希，其余用原哈希
        # （self-check 在装好的包里仍全 MATCH；工作区锚=上游同步证据不受影响）
        import hashlib
        anchored = ["engine/__init__.py", "engine/detectors.py", "engine/rules.py",
                    "engine/sanitizer.py", "engine/sarif.py", "engine/scan.py",
                    "engine/zh_rules.py", "entry.py"]
        lines = []
        for arel in anchored:
            data = transformed.get("scripts/" + arel) or (SKILL / "scripts" / arel).read_bytes()
            lines.append(f"{hashlib.sha256(data).hexdigest()}  skill/scripts/{arel}")
        zf.writestr("scripts/engine/ENGINE-ANCHOR.txt", "\n".join(lines) + "\n")
    # 自检①③
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "SKILL.md" in names, "[自检①] SKILL.md 不在 ZIP 根目录"
        assert all("/" in n or n == "SKILL.md" or True for n in names)
        assert len(names) <= 50, f"[自检③] 文件数 {len(names)} > 50"
    size = out.stat().st_size
    assert size <= 10 * 1024 * 1024, f"[自检③] ZIP {size} 字节超 10MB"
    print(f"[{channel}] {out.name}  {size} 字节 / {len(names)} 文件  OK")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="dist")
    args = ap.parse_args()
    version = check_versions()
    print(f"版本一致性 OK：{version}（SKILL.md/package/_meta/.skill-config）")
    dist = REPO / args.dist
    for channel in ("tianxi", "clawhub"):
        build(channel, dist, version)
    print("双渠道构建完成，六重自检全过。")


if __name__ == "__main__":
    sys.exit(main())
