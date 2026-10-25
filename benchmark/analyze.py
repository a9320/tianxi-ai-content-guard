#!/usr/bin/env python3
"""触发率统计：扫天禧 session JSONL，识别 ai-content-guard 实际调用，对齐用例。

用法：
    python benchmark/analyze.py --since "2026-10-25T10:00"     # 只统计此后会话
    python benchmark/analyze.py --minutes 120                  # 或最近 N 分钟

判定标准（docs/trigger-benchmark.md）：会话 JSONL 中出现 entry.py 执行痕迹
（含 ai-content-guard 且含 scripts/entry.py 或 [ai-content-guard] 标记）
= 已触发；模型自述不算。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
from pathlib import Path

PROJECTS = Path(r"C:\ProgramData\Lenovo\AIAgent\xlagent\projects")
REPO = Path(__file__).resolve().parents[1]
TRIGGER_PAT = re.compile(r"ai-content-guard.{0,120}(scripts[\\/]entry\.py|\[ai-content-guard\])"
                         r"|(?:scripts[\\/]entry\.py|\[ai-content-guard\]).{0,120}ai-content-guard",
                         re.S)


def wilson(p: float, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    c = p + z * z / (2 * n)
    d = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - d) / (1 + z * z / n), (c + d) / (1 + z * z / n))


def iter_sessions(since: dt.datetime):
    for jf in PROJECTS.rglob("*.jsonl"):
        try:
            mtime = dt.datetime.fromtimestamp(jf.stat().st_mtime)
        except OSError:
            continue
        if mtime < since:
            continue
        try:
            lines = jf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        first_user, model, triggered = "", None, False
        for ln in lines:
            if triggered and first_user and model:
                break
            if "ai-content-guard" in ln and TRIGGER_PAT.search(ln):
                triggered = True
            if not model:
                m = re.search(r'"model"\s*:\s*"([^"]+)"', ln)
                if m:
                    model = m.group(1)
            if not first_user:
                if '"role"' in ln and '"user"' in ln:
                    m = re.search(r'"content"\s*:\s*"([^"]{0,160})', ln)
                    if m and not m.group(1).startswith("<"):
                        first_user = m.group(1)
        yield {"file": jf.name, "mtime": mtime, "triggered": triggered,
               "model": model, "first_user": first_user}


def align(sessions, cases):
    """把会话按首条用户消息前缀对齐到用例（朴素匹配，人工核对兜底）。"""
    by_id: dict[str, list] = {}
    unmatched = []
    for s in sessions:
        hit = None
        head = re.sub(r"\s+", "", s["first_user"])[:24]
        for c in cases:
            if re.sub(r"\s+", "", c["prompt"])[:24] == head or (
                    len(s["first_user"]) > 12 and s["first_user"][:12] in c["prompt"]):
                hit = c["id"]
                break
        (by_id.setdefault(hit, []) if hit else unmatched).append(s)
    return by_id, unmatched


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", help="ISO 时间，如 2026-10-25T10:00")
    ap.add_argument("--minutes", type=int, help="只统计最近 N 分钟")
    ap.add_argument("--exclude-session", action="append", default=[],
                    help="排除指定会话（文件名含此 ID 即排除，可多次）")
    ap.add_argument("--exclude-window", action="append", default=[],
                    help="排除时间窗 START,END（ISO，如 2026-10-25T14:49,2026-10-25T15:00，可多次）")
    args = ap.parse_args()
    if args.minutes:
        since = dt.datetime.now() - dt.timedelta(minutes=args.minutes)
    elif args.since:
        since = dt.datetime.fromisoformat(args.since)
    else:
        since = dt.datetime.now() - dt.timedelta(hours=6)

    def _excluded(s) -> bool:
        if any(sid in s["file"] for sid in args.exclude_session):
            return True
        for w in args.exclude_window:
            try:
                a, b = w.split(",")
                if dt.datetime.fromisoformat(a) <= s["mtime"] <= dt.datetime.fromisoformat(b):
                    return True
            except ValueError:
                continue
        return False

    cases = json.loads((REPO / "benchmark" / "cases.json").read_text(encoding="utf-8"))["cases"]
    sessions = [s for s in sorted(iter_sessions(since), key=lambda s: s["mtime"])
                if not _excluded(s)]
    print(f"窗口内会话：{len(sessions)}（自 {since.isoformat(timespec='minutes')}）\n")
    for s in sessions:
        mark = "✅触发" if s["triggered"] else "—"
        print(f"[{mark}] {s['mtime']:%H:%M} model={s['model']} | {s['first_user'][:60]}")

    by_id, unmatched = align(sessions, cases)
    pos = [c for c in cases if c["category"].endswith("positive")]
    neg = [c for c in cases if c["category"].endswith("negative")]
    stat = {"positive": [0, 0], "negative": [0, 0]}
    print("\n## 对齐结果")
    for c in cases:
        runs = by_id.get(c["id"], [])
        trig = sum(1 for r in runs if r["triggered"])
        bucket = "positive" if c["category"].endswith("positive") else "negative"
        stat[bucket][0] += trig
        stat[bucket][1] += len(runs)
        if runs:
            print(f"  {c['id']}: {trig}/{len(runs)}")
    p_t, p_n = stat["positive"]
    n_t, n_n = stat["negative"]
    print(f"\n正向触发率：{p_t}/{p_n}" + (f" = {p_t / p_n:.0%} CI95 {wilson(p_t / p_n, p_n)}" if p_n else ""))
    print(f"负向误触发率：{n_t}/{n_n}" + (f" = {n_t / n_n:.0%} CI95 {wilson(n_t / n_n, n_n)}" if n_n else ""))
    print(f"未对齐会话 {len(unmatched)} 个（人工归类）")
    print("验收门槛：正向≥80% / 负向≤10%（每例 3 次）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
