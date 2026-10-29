#!/usr/bin/env python3
"""30×3 触发率统计（v2）：读天禧官方会话 JSONL，按用例对齐，支持按批/合并。

修正 2026-10-29：
  - 首条 human prompt 取 `humanInput.text` 或 message.content，排除 tool_result；
  - 只从 assistant tool_use / tool_result 判定触发，避免把 skill 正文里的示例命令
    当成执行痕迹；
  - 支持 --until / --sessions / --label / --fixture-dir，按批检查；
  - 输出每例 runs/triggers、正/负触发率（Wilson）、不稳定率（需每例 3 次）。

用法：
  python benchmark/analyze.py --since "2026-10-28 22:00" --until "2026-10-28 23:30" --label "批1"
  python benchmark/analyze.py --since "2026-10-28 22:00" --until "2026-10-29 01:00" --label "30x3"
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
from pathlib import Path

DEFAULT_SESSIONS = Path(os.environ.get(
    "ACG_PROJECTS",
    r"C:\ProgramData\Lenovo\AIAgent\xlagent\projects\C--Users-Lenovo-Tianxi"))
DEFAULT_FIXTURE = Path(os.environ.get("ACG_FIXTURES", r"C:\Users\Lenovo\acg-bench"))
REPO = Path(__file__).resolve().parents[1]
CASES = json.loads((REPO / "benchmark" / "cases.json").read_text(encoding="utf-8"))["cases"]
SCAN_FLAG = re.compile(r"--(?:text|file|dir|decode)\b")


def wilson(p: float, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    c = p + z * z / (2 * n)
    d = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - d) / (1 + z * z / n), (c + d) / (1 + z * z / n))


def norm(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def records_of(path: Path):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def first_human_prompt(recs) -> str:
    for d in recs:
        if d.get("type") != "user":
            continue
        if d.get("toolUseResult") or d.get("sourceToolAssistantUUID"):
            continue
        hi = d.get("humanInput")
        text = hi.get("text") if isinstance(hi, dict) else None
        if not text:
            msg = d.get("message") or {}
            content = msg.get("content") if isinstance(msg, dict) else None
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                parts = [b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text"]
                text = "\n".join(p for p in parts if p)
        if not text:
            continue
        text = text.strip()
        if text.startswith("<") or text.startswith("Base directory for this skill:"):
            continue
        if text.startswith("Launching skill:"):
            continue
        return text
    return ""


def is_triggered(recs) -> bool:
    for d in recs:
        if d.get("type") == "assistant":
            msg = d.get("message") or {}
            for b in (msg.get("content") or []) if isinstance(msg, dict) else []:
                if not isinstance(b, dict) or b.get("type") != "tool_use":
                    continue
                blob = json.dumps(b.get("input") or {}, ensure_ascii=False)
                if "entry.py" in blob and SCAN_FLAG.search(blob):
                    return True
        elif d.get("type") == "user":
            msg = d.get("message") or {}
            for b in (msg.get("content") or []) if isinstance(msg, dict) else []:
                if not isinstance(b, dict) or b.get("type") != "tool_result":
                    continue
                content = b.get("content")
                text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
                if "[ai-content-guard]" in text and ("engine=" in text or '"verdict"' in text):
                    return True
    return False


def model_of(recs):
    for d in recs:
        if d.get("type") == "runtime-config" and d.get("model"):
            return d.get("model")
    for d in recs:
        if isinstance(d.get("model"), str):
            return d["model"]
    return None


def match_case(prompt: str, prepared):
    p = norm(prompt)
    if not p:
        return None
    for cid, cp, c in prepared:
        if p == cp:
            return cid
    for cid, cp, c in sorted(prepared, key=lambda x: len(x[1]), reverse=True):
        if len(cp) >= 30 and p.startswith(cp):
            return cid
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default=None, help="YYYY-MM-DD HH:MM 或 ISO")
    ap.add_argument("--until", default=None, help="同上；不填=现在")
    ap.add_argument("--minutes", type=int, default=None)
    ap.add_argument("--sessions", default=str(DEFAULT_SESSIONS))
    ap.add_argument("--fixture-dir", default=str(DEFAULT_FIXTURE))
    ap.add_argument("--exclude-session", action="append", default=[])
    ap.add_argument("--exclude-window", action="append", default=[],
                    help="START,END（可多次）")
    ap.add_argument("--label", default="30x3")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.minutes:
        since = dt.datetime.now() - dt.timedelta(minutes=args.minutes)
    elif args.since:
        since = dt.datetime.fromisoformat(args.since)
    else:
        since = dt.datetime.now() - dt.timedelta(hours=6)
    until = dt.datetime.fromisoformat(args.until) if args.until else dt.datetime.now()

    def excluded(mtime: dt.datetime) -> bool:
        for w in args.exclude_window:
            try:
                a, b = w.split(",")
                if dt.datetime.fromisoformat(a) <= mtime <= dt.datetime.fromisoformat(b):
                    return True
            except ValueError:
                continue
        return False

    prepared = []
    for c in CASES:
        prompt = c["prompt"].replace("{FIXTURE}", str(Path(args.fixture_dir)))
        prepared.append((c["id"], norm(prompt), c))

    sessions = []
    root = Path(args.sessions)
    for jf in root.rglob("*.jsonl"):
        try:
            mtime = dt.datetime.fromtimestamp(jf.stat().st_mtime)
        except OSError:
            continue
        if mtime < since or mtime > until or excluded(mtime):
            continue
        if any(sid in jf.name for sid in args.exclude_session):
            continue
        recs = list(records_of(jf))
        prompt = first_human_prompt(recs)
        cid = match_case(prompt, prepared)
        sessions.append({
            "file": jf.name, "mtime": mtime, "case": cid,
            "triggered": is_triggered(recs), "model": model_of(recs),
        })

    sessions.sort(key=lambda s: s["mtime"])
    by_id: dict[str, list] = {}
    unmatched = []
    for s in sessions:
        if s["case"]:
            by_id.setdefault(s["case"], []).append(s)
        else:
            unmatched.append(s)

    rows = []
    pos_t = pos_n = neg_t = neg_n = 0
    unstable = 0
    all_three = True
    for cid, cp, c in prepared:
        runs = by_id.get(cid, [])
        trig = sum(1 for r in runs if r["triggered"])
        is_pos = c["category"].endswith("positive")
        if is_pos:
            pos_t += trig
            pos_n += len(runs)
        else:
            neg_t += trig
            neg_n += len(runs)
        if len(runs) != 3:
            all_three = False
        if len(runs) >= 2 and 1 <= trig <= 2:
            unstable += 1
        rows.append({"id": cid, "category": c["category"], "runs": len(runs),
                     "triggers": trig, "sessions": [r["file"] for r in runs]})

    out = {
        "label": args.label,
        "window": [since.isoformat(timespec="minutes"), until.isoformat(timespec="minutes")],
        "sessions": len(sessions), "unmatched": len(unmatched),
        "rows": rows,
        "positive": {"triggers": pos_t, "runs": pos_n},
        "negative": {"triggers": neg_t, "runs": neg_n},
        "unstable": unstable if all_three else None,
        "all_cases_three_runs": all_three,
    }
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return 0

    print(f"== {args.label} ==")
    print(f"窗口：{since:%Y-%m-%d %H:%M} → {until:%Y-%m-%d %H:%M}；会话 {len(sessions)}；未对齐 {len(unmatched)}")
    print(f"\n{'用例':4} {'类别':24} {'runs':>4} {'触发':>4}")
    for r in rows:
        if r["runs"]:
            print(f"{r['id']:4} {r['category']:24} {r['runs']:>4} {r['triggers']:>4}")
    def rate(t, n):
        return f"{t}/{n} = {t/n:.0%} CI95 {wilson(t/n, n)}" if n else f"{t}/{n} = N/A"
    print(f"\n正向触发率：{rate(pos_t, pos_n)}")
    print(f"负向误触发率：{rate(neg_t, neg_n)}")
    if all_three:
        print(f"不稳定用例：{unstable}/30 = {unstable/30:.0%}")
    else:
        print("不稳定用例：N/A（需每例 3 次；本批为单次检查）")
    print("验收门槛：正向≥80% / 负向≤10% / 不稳定≤20%（3 批合并）")
    if unmatched:
        print("\n未对齐会话（只列文件，不打印内容）：")
        for s in unmatched:
            print(f"  {s['mtime']:%Y-%m-%d %H:%M} {s['file']} model={s['model']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())