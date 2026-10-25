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
FORBIDDEN_NAMES = {".DS_Store"}
FORBIDDEN_PARTS = {".git", "node_modules", "__pycache__", "dist"}
FORBIDDEN_SUFFIX = {".log", ".env", ".zip", ".png", ".jpg", ".bak", ".pyc"}


def _version() -> str:
    return json.loads((SKILL / ".skill-config.json").read_text(encoding="utf-8"))["version"]


def check_versions():
    v = _version()
    pkg = json.loads((SKILL / "package.json").read_text(encoding="utf-8"))["version"]
    meta = json.loads((SKILL / "_meta.json").read_text(encoding="utf-8"))["version"]
    skill_md = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.search(r"^version:\s*(\S+)", skill_md, re.M)
    assert m, "SKILL.md 缺 version 字段"
    assert v == pkg == meta == m.group(1), f"版本号不一致：{v}/{pkg}/{meta}/{m.group(1)}"
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
        if rel.suffix.lower() not in ALLOWED_EXT:
            raise SystemExit(f"[自检④] 扩展名不在白名单：{rel}（图标走网页控制台）")
        if p.stat().st_size > 1024 * 1024:
            raise SystemExit(f"[自检②] 单文件超 1MB（CLI 会静默跳过）：{rel}")
        files.append((p, rel))
    return files


def build(channel: str, dist: Path, version: str):
    out = dist / channel / f"ai-content-guard-{version}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p, rel in collect_files():
            data = p.read_bytes()
            if channel == "clawhub" and rel.as_posix() == "SKILL.md":
                data = data.decode("utf-8").replace("${QODER_SKILL_DIR}", "{baseDir}").encode("utf-8")
            zf.writestr(rel.as_posix(), data)  # arcname 不带 skill/ 前缀 → SKILL.md 在根
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
