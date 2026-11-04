#!/usr/bin/env python3
"""构建魔搭（ModelScope）渠道发行树。

魔搭 Skills 中心遵循 Anthropic Agent Skills 协议（SKILL.md + scripts/ + references/），
且以 Git 仓库方式托管（`https://www.modelscope.cn/skills/<owner>/<name>.git`）。

与天禧包差异：
  - 不含 package.json / _meta.json / .skill-config.json（天禧 CLI 专用字段）
  - 追加 skill-card.md（社区信任卡片，模板见 build/modelscope/skill-card.md）
  - SKILL.md 保持 `<skill 目录>` 通用写法（协议由宿主注入 Base directory）

产物：
  dist/modelscope/ai-content-guard/                 ← 可直接 git push 的工作树
  dist/modelscope/ai-content-guard-<version>.zip   ← 网页上传用

用法：python build/build_modelscope.py [--dist dist]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import shutil
import sys
import zipfile
from pathlib import Path

BUILD_DIR = Path(__file__).resolve().parent
REPO = BUILD_DIR.parent
SKILL = REPO / "skill"
SKILL_CARD = BUILD_DIR / "modelscope" / "skill-card.md"

# 天禧专用文件，魔搭不需要
EXCLUDE = {"package.json", "_meta.json", ".skill-config.json"}
# 锚文件按发行内容重算（与天禧构建同口径）
ANCHORED = ["engine/__init__.py", "engine/detectors.py", "engine/rules.py",
            "engine/sanitizer.py", "engine/sarif.py", "engine/scan.py",
            "engine/zh_rules.py", "entry.py"]


def _load_build_module():
    spec = importlib.util.spec_from_file_location("cg_build", BUILD_DIR / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="dist")
    args = ap.parse_args()

    build_mod = _load_build_module()
    version = build_mod.check_versions()
    print(f"版本一致性 OK：{version}")

    out_root = REPO / args.dist / "modelscope"
    tree = out_root / "ai-content-guard"
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)

    written: dict[str, bytes] = {}
    for p, rel in build_mod.collect_files():
        if rel.name in EXCLUDE:
            continue
        data = p.read_bytes()
        if rel.suffix == ".py":
            data = build_mod._sanitize_engine(rel, data)
        # 统一 LF：跨平台注册表的 frontmatter/脚本解析不应依赖 CRLF
        if rel.suffix in {".md", ".py", ".txt", ".json", ".yaml", ".yml"}:
            data = data.replace(b"\r\n", b"\n")
        written[rel.as_posix()] = data

    # skill-card.md（信任卡片）
    written["skill-card.md"] = SKILL_CARD.read_bytes().replace(b"\r\n", b"\n")

    # .gitattributes：强制 LF 检出。否则 Windows 默认 core.autocrlf=true 会在
    # clone 时把 LF 转 CRLF，导致 ENGINE-ANCHOR 的字节哈希全部 MISMATCH。
    written[".gitattributes"] = b"* text=auto eol=lf\n"

    # 包内完整性锚：按最终发行内容重算
    lines = []
    for arel in ANCHORED:
        data = written.get(f"scripts/{arel}")
        if data is None:
            data = (SKILL / "scripts" / arel).read_bytes()
        lines.append(f"{hashlib.sha256(data).hexdigest()}  skill/scripts/{arel}")
    written["scripts/engine/ENGINE-ANCHOR.txt"] = ("\n".join(lines) + "\n").encode()

    for rel_posix, data in sorted(written.items()):
        target = tree / rel_posix
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    # 自检
    assert (tree / "SKILL.md").is_file(), "SKILL.md 必须位于仓库根"
    total = sum(len(d) for d in written.values())
    assert total <= 10 * 1024 * 1024, f"总大小 {total} 超 10MB"
    assert len(written) <= 50, f"文件数 {len(written)} 超 50"

    # zip（网页上传用）
    zp = out_root / f"ai-content-guard-{version}.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_posix, data in sorted(written.items()):
            zf.writestr(rel_posix, data)

    print(f"[modelscope] 工作树 {tree}")
    print(f"[modelscope] {zp.name}  {zp.stat().st_size} 字节 / {len(written)} 文件  OK")
    for rel_posix in sorted(written):
        print(f"  - {rel_posix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())