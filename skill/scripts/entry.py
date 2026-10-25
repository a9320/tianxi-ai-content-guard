#!/usr/bin/env python3
"""ai-content-guard 统一入口 — AI 内容安检（PITAX 确定性引擎 + 信封输出）。

架构宪法（docs/design-decisions.md）：
  1. 判决权归引擎：verdict/counts/去重/脱敏全部由本脚本确定性产出，模型只解释；
  2. 三层输出：聊天只回紧凑信封（≤8k），完整 findings 落 report.jsonl，人读摘要 summary.md；
  3. 注入防御：脚本预脱敏——被检内容的原文永不进入模型上下文。

铁律：纯标准库 / 零网络 / 只读扫描 / 永不执行被检内容 / 失败返回结构化错误。

用法：
    python entry.py --text "粘贴的邮件/消息/文档内容"
    python entry.py --file "C:\\path\\to\\可疑文件.md"     （--file - 读 stdin）
    python entry.py --dir  "C:\\path\\to\\repo"             （--mode config 只审 AI 配置文件）
    python entry.py --decode "SGVsbG8..."                   （编码载荷分层复核，≤3 层）
    python entry.py --self-check                            （边界自证：网络/写盘/动态执行/规则哈希）

退出码：0=完成；1=--fail-on 命中；2=参数错误；3=运行时错误。
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

# ── 编码三件套（第 1 件）：天禧自带 Python 3.14 的控制台默认 GBK，先改 UTF-8 ──
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from engine.detectors import is_ai_config_path  # noqa: E402
from engine.rules import ALL_RULES, PITAX_VERSION  # noqa: E402
from engine.sanitizer import MAX_FILE_BYTES, SCAN_EXTENSIONS, SKIP_DIRS  # noqa: E402
from engine.sarif import build_sarif  # noqa: E402
from engine.scan import scan_file, scan_repo  # noqa: E402

SKILL_NAME = "ai-content-guard"
SKILL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

# ── 扫描防护上限（对齐 docs/design-decisions.md 八条）──
DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_BYTES = 200 * 1024 * 1024
DEFAULT_MAX_DEPTH = 20
DEFAULT_TIMEOUT_S = 30

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 系统目录拒绝清单（realpath 后按路径隶属判断，绝不做字符串前缀匹配）
_SYSTEM_DIRS = [
    Path(os.environ.get("WINDIR", r"C:\Windows")),
    Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)"),
    Path(r"C:\ProgramData"),
    Path("/etc"), Path("/usr"), Path("/bin"), Path("/sbin"),
    Path("/System"), Path("/Library"), Path("/private"), Path("/var"),
]

# 敏感文件：只报存在，绝不读内容、不展示内容
_SENSITIVE_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*",
    "credentials*", "cookies*", "Login Data", "*.sqlite", "*.db",
    "NTDS.dit", "SAM", "SECURITY", "*.kdbx", "*.pfx", "*.p12", "*.wallet",
]

# 贴入文本的多路由虚拟名：同一内容走"文档路径(N-06)"与"代码路径(4 检测器)"两趟；
# 另抽 base64 候选串构造带引号的虚拟代码行——引擎 E-57 只认字符串字面量（防误报
# 设计），裸文本中的编码载荷须经此适配才能进入剥离链。
_TEXT_VIRTUAL_NAMES = ["pasted-content.md", "pasted-content.py"]
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_MAX_PAYLOAD_CANDIDATES = 64

_BINARY_SNIFF_BYTES = 8192
_DECODE_CHAIN = ("utf-8-sig", "utf-8", "gb18030", "utf-16")

# 零宽/双向控制符（输出时以 U+XXXX 记法呈现，原字符不进任何输出）
_INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u00ad]")
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
_B64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


# ══════════════════════ 基础工具 ══════════════════════

def _decode_bytes(data: bytes) -> str:
    """编码三件套（第 3 件）：文件/stdin 按链解码，全部失败则替换解码。"""
    for enc in _DECODE_CHAIN:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _sha8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:8]


def _is_under(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def guard_root(raw: str) -> Path:
    """防护①：规范化 + 系统目录拒绝。"""
    root = Path(raw).expanduser().resolve()
    for d in _SYSTEM_DIRS:
        try:
            if _is_under(root, d.expanduser().resolve()):
                raise ValueError(f"拒绝扫描系统目录：{root}")
        except OSError:
            continue
    return root


def _is_sensitive(rel: str) -> bool:
    name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return any(fnmatch.fnmatch(name, pat.lower()) for pat in _SENSITIVE_PATTERNS)


def _is_reparse(entry) -> bool:
    """防护②：符号链接与 Windows junction/reparse point 都不跟随。"""
    if entry.is_symlink():
        return True
    try:
        return bool(entry.stat(follow_symlinks=False).st_file_attributes & 0x400)
    except (AttributeError, OSError):
        return False


# ══════════════════════ 输入采集 ══════════════════════

def _read_file_bytes(path: Path) -> bytes:
    """防护⑤/⑥：只读打开 + 二进制嗅探跳过 + 单文件上限。"""
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"文件超过单文件上限（{MAX_FILE_BYTES // 1024}KB）：{path}")
    with open(path, "rb") as fh:  # noqa: SIM115 - 显式只读
        head = fh.read(_BINARY_SNIFF_BYTES)
        if b"\x00" in head:
            raise ValueError(f"二进制文件，跳过：{path.name}")
        return head + fh.read()


def collect_dir(root: Path, max_files: int, max_bytes: int,
                max_depth: int, timeout_s: int, config_only: bool = False):
    """目录采集：八条防护中的①②③④⑥⑧在此落地。返回 (files, coverage, errors)。"""
    files: dict[str, str] = {}
    errors: list[str] = []
    coverage = {
        "root": str(root), "files_scanned": 0, "files_skipped": 0,
        "sensitive_skipped": [], "bytes_scanned": 0, "truncated": False,
        "limits": ["确定性层仅覆盖 PITAX 规则集；语义改写类攻击不在本层覆盖内"],
    }
    deadline = time.monotonic() + timeout_s
    stopped = None

    def walk(dir_path: Path, depth: int) -> None:
        nonlocal stopped
        if stopped or depth > max_depth:
            return
        try:
            entries = sorted(os.scandir(dir_path), key=lambda e: e.name)
        except (PermissionError, OSError) as exc:
            errors.append(f"目录不可读（{type(exc).__name__}）：{dir_path}")
            return
        for entry in entries:
            if stopped:
                return
            if time.monotonic() > deadline:
                stopped = "timeout"
                coverage["truncated"] = True
                coverage["limits"].append(f"达到 {timeout_s}s 超时上限，未扫完")
                return
            if entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS:
                    continue
                if _is_reparse(entry):
                    continue
                walk(Path(entry.path), depth + 1)
                continue
            if not entry.is_file(follow_symlinks=False) or _is_reparse(entry):
                continue
            rel = str(Path(entry.path).relative_to(root)).replace("\\", "/")
            if _is_sensitive(rel):  # 防护③：敏感文件只报存在
                if len(coverage["sensitive_skipped"]) < 20:
                    coverage["sensitive_skipped"].append(rel)
                coverage["files_skipped"] += 1
                continue
            if config_only and not is_ai_config_path(rel):
                continue
            try:
                if entry.stat(follow_symlinks=False).st_size > MAX_FILE_BYTES:
                    coverage["files_skipped"] += 1
                    continue
                data = _read_file_bytes(Path(entry.path))
            except ValueError as exc:
                coverage["files_skipped"] += 1
                if "二进制" not in str(exc):
                    errors.append(str(exc))
                continue
            except (PermissionError, OSError) as exc:
                errors.append(f"文件不可读（{type(exc).__name__}）：{rel}")  # 防护⑧
                coverage["files_skipped"] += 1
                continue
            if len(files) >= max_files or coverage["bytes_scanned"] + len(data) > max_bytes:
                stopped = "caps"
                coverage["truncated"] = True
                coverage["limits"].append(
                    f"达到 max-files={max_files} / max-bytes={max_bytes // (1024 * 1024)}MB 上限，未扫完")
                return
            files[rel] = _decode_bytes(data)
            coverage["files_scanned"] += 1
            coverage["bytes_scanned"] += len(data)

    walk(root, 0)
    return files, coverage, errors


def collect_text(text: str):
    """贴入文本：同一内容按多路由虚拟名扫描，命中去重。"""
    seen: set[tuple] = set()
    findings: list[dict] = []
    for virtual in _TEXT_VIRTUAL_NAMES:
        for f in scan_file(virtual, text, _n=1):
            key = (f.get("type"), f.get("line"), (f.get("code_snippet") or "")[:120])
            if key in seen:
                continue
            seen.add(key)
            f = dict(f)
            f["file"] = "<粘贴内容>"
            findings.append(f)
    # 编码载荷适配：base64 候选串 → 带引号虚拟代码行 → 引擎剥离链（E-07/14/36/57）
    candidates = _B64_RUN_RE.findall(text)[:_MAX_PAYLOAD_CANDIDATES]
    if candidates:
        virtual_code = "\n".join('payload = "%s"' % b for b in candidates)
        for f in scan_file("pasted-payloads.py", virtual_code, _n=1):
            key = (f.get("type"), "enc", (f.get("code_snippet") or "")[:120])
            if key in seen:
                continue
            seen.add(key)
            f = dict(f)
            f["file"] = "<粘贴内容·编码载荷>"
            findings.append(f)
    coverage = {
        "root": "<粘贴文本>", "files_scanned": 1, "files_skipped": 0,
        "sensitive_skipped": [], "bytes_scanned": len(text.encode("utf-8", errors="replace")),
        "truncated": False,
        "limits": ["确定性层仅覆盖 PITAX 规则集；语义改写类攻击不在本层覆盖内"],
    }
    return findings, coverage, []


# ══════════════════════ 脱敏（架构宪法③：原文不进模型上下文）══════════════════════

def _notation_invisible(text: str) -> str:
    return _INVISIBLE_RE.sub(
        lambda m: "‹U+%04X›" % ord(m.group(0)), text)


def redact_fragment(raw: str, limit: int = 40) -> str:
    """按 F6 规范脱敏：隐形字符记法化 + 长编码串取前后缀 + 可见片段截断。"""
    out = _notation_invisible(raw)
    out = _LONG_TOKEN_RE.sub(lambda m: m.group(0)[:8] + "…" + m.group(0)[-8:], out)
    out = out.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return out[:limit]


def redact_finding(f: dict) -> dict:
    """输出前逐条脱敏：证据/解码载荷只保留 记法+长度+SHA8+短片段。"""
    evidence = (f.get("code_snippet") or "")[:240]
    decoded = f.get("pitax", {}).get("decoded_payload") if isinstance(f.get("pitax"), dict) else None
    red = {
        "id": f.get("id"),
        "type": f.get("type"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "title": f.get("title"),
        "file": f.get("file"),
        "line": f.get("line"),
        "evidence_redacted": "[{code}] len={len} sha={sha} frag={frag}".format(
            code=f.get("type"), len=len(evidence), sha=_sha8(evidence),
            frag=redact_fragment(evidence)),
        "description": f.get("description"),
        "advice": f.get("suggestion"),
    }
    if decoded:
        red["decoded_redacted"] = "[decoded] len={len} sha={sha} frag={frag}".format(
            len=len(decoded), sha=_sha8(decoded), frag=redact_fragment(str(decoded)))
    return red


# ══════════════════════ 四值判决聚合 ══════════════════════

def aggregate(findings: list[dict], coverage: dict, errors: list[str]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[str(f.get("severity", "info")).lower()] = counts.get(
            str(f.get("severity", "info")).lower(), 0) + 1
    if counts["critical"] or counts["high"]:
        verdict, confidence = "malicious", 0.9
    elif counts["medium"] or counts["low"] or counts["info"]:
        verdict, confidence = "suspicious", 0.7
    elif errors or coverage.get("truncated"):
        verdict, confidence = "inconclusive", 0.3
        if errors:
            coverage["limits"].append(f"扫描过程 {len(errors)} 项错误，覆盖不完整")
    else:
        verdict, confidence = "clean", 0.9
    return {"verdict": verdict, "verdict_source": "engine",
            "confidence": confidence, "counts": counts}


# ══════════════════════ 输出三件套 ══════════════════════

def _risk_word(verdict: str) -> str:
    return {"malicious": "高风险", "suspicious": "可疑",
            "clean": "未检出", "inconclusive": "无法完成"}.get(verdict, verdict)


def build_summary_text(agg: dict, coverage: dict) -> str:
    c = agg["counts"]
    hot = c["critical"] + c["high"]
    if agg["verdict"] == "malicious":
        head = f"检出 {hot} 项高危（critical {c['critical']} / high {c['high']}）"
    elif agg["verdict"] == "suspicious":
        head = f"检出 {c['medium'] + c['low']} 项可疑信号"
    elif agg["verdict"] == "inconclusive":
        head = "扫描未完整完成，不下安全结论"
    else:
        head = "在已覆盖范围内未检出 AI 攻击特征"
    return (f"{head}；覆盖 {coverage.get('files_scanned', 0)} 个文件 / "
            f"{coverage.get('bytes_scanned', 0)} 字节"
            + ("（已截断，未扫完）" if coverage.get("truncated") else "") + "。")


def write_reports(findings: list[dict], agg: dict, coverage: dict,
                  out_dir: Path | None) -> dict:
    """findings>10 或用户 --out 时落盘 report.jsonl + summary.md（证据为脱敏形态）。"""
    target = out_dir or Path(tempfile.gettempdir()) / f"{SKILL_NAME}-{int(time.time())}"
    target.mkdir(parents=True, exist_ok=True)
    reds = [redact_finding(f) for f in findings]
    (target / "report.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in reds) + "\n",
        encoding="utf-8")
    lines = [f"# AI 内容安检报告（{SKILL_NAME} v{SKILL_VERSION}）", "",
             f"- 判决：**{_risk_word(agg['verdict'])}**（verdict={agg['verdict']}，"
             f"来源=引擎，confidence={agg['confidence']}）",
             f"- 计数：{json.dumps(agg['counts'], ensure_ascii=False)}",
             f"- 覆盖：{coverage.get('files_scanned', 0)} 文件 / "
             f"{coverage.get('bytes_scanned', 0)} 字节"
             + ("（截断）" if coverage.get("truncated") else ""), ""]
    if coverage.get("sensitive_skipped"):
        lines.append(f"- 敏感文件仅报存在（未读取）：{', '.join(coverage['sensitive_skipped'])}")
    lines += ["## 命中明细（证据已脱敏）", ""]
    for r in reds:
        lines += [f"- **[{r['severity']}] {r['title']}** `{r['file']}:{r['line']}`",
                  f"  - {r['evidence_redacted']}",
                  f"  - 建议：{r.get('advice')}", ""]
    lines += ["---", "*零命中仅代表当前规则集未发现命中，不代表内容绝对安全。*",
              f"*依据 Arcanum Prompt Injection Taxonomy v{PITAX_VERSION}（CC BY 4.0）。*"]
    (target / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    return {"report_path": str(target / "report.jsonl"),
            "summary_path": str(target / "summary.md")}


def build_envelope(findings: list[dict], agg: dict, coverage: dict,
                   report_paths: dict | None, elapsed_ms: int) -> dict:
    top = sorted(findings, key=lambda f: _SEVERITY_RANK.get(
        str(f.get("severity", "info")).lower(), 4))[:10]
    env = {
        "schema_version": SCHEMA_VERSION, "skill": SKILL_NAME,
        "skill_version": SKILL_VERSION, "pitax_version": PITAX_VERSION,
        "ok": True, "verdict": agg["verdict"], "verdict_source": "engine",
        "confidence": agg["confidence"],
        "summary": build_summary_text(agg, coverage),
        "ambient": {"one_liner": (
            f"安检通过：{build_summary_text(agg, coverage)}"
            if agg["verdict"] == "clean" else
            f"⚠️ {build_summary_text(agg, coverage)}——建议先查看报告再决定是否采用该内容")},
        "counts": agg["counts"], "coverage": coverage,
        "top_findings": [redact_finding(f) for f in top],
        "elapsed_ms": elapsed_ms,
        "limits": ["零命中仅代表当前规则集未发现命中，不代表内容绝对安全"],
    }
    if report_paths:
        env.update(report_paths)
    return env


# ══════════════════════ stdin 宽容解析 ══════════════════════

def _unwrap_stdin_json(obj) -> str | None:
    """五形态宽容解析：{"params":{"input":..}} / {"input":..} / text/content/prompt / 裸文本。"""
    if isinstance(obj, dict):
        if isinstance(obj.get("params"), dict):
            obj = obj["params"]
        for key in ("input", "text", "content", "prompt"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                return v
    return None


def read_stdin_text() -> str:
    """编码三件套（第 2 件）：stdin 读原始字节，链解 + JSON 宽容解包，兜底裸文本。"""
    raw = sys.stdin.buffer.read()
    if not raw:
        return ""
    text = None
    try:
        text = _unwrap_stdin_json(json.loads(raw.decode("utf-8-sig")))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        text = None
    return text if text is not None else _decode_bytes(raw)


# ══════════════════════ 自检与解码复核 ══════════════════════

def self_check() -> int:
    engine_dir = _SCRIPT_DIR / "engine"
    print(f"{SKILL_NAME} v{SKILL_VERSION} self-check")
    print(f"python: {sys.version.split()[0]}   pitax: v{PITAX_VERSION}   rules: {len(ALL_RULES)}")
    print("network: none（无 requests/urllib/socket/http.client 导入，零联网）")
    print("dynamic execution: none（无 eval/exec/compile/os.system/subprocess/pickle.loads）")
    print("writes: none by default（仅 findings>10 或 --out 时写脱敏报告到指定/临时目录）")
    print("reads: 只读用户指定路径；系统目录拒绝；敏感文件只报存在；符号链接/junction 不跟随")
    anchor = engine_dir / "ENGINE-ANCHOR.txt"
    for p in sorted(engine_dir.glob("*.py")):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"engine file: {p.name}  sha256={h[:16]}…")
    if anchor.exists():
        expect = {ln.split("  ", 1)[1].strip().split("/")[-1]: ln.split("  ")[0]
                  for ln in anchor.read_text(encoding="utf-8").splitlines() if "  " in ln}
        for name, want in expect.items():
            got = hashlib.sha256((engine_dir / name).read_bytes()).hexdigest()
            print(f"anchor: {name}  {'MATCH' if got == want else 'MISMATCH!!'}")
    return 0


def decode_review(payload: str) -> int:
    """编码载荷分层复核（≤3 层 / ≤64KB，只解码匹配，不执行）。"""
    data = payload[:64 * 1024]
    print(f"输入 len={len(payload)} sha={_sha8(payload)}")
    for layer in range(1, 4):
        cand = data.strip()
        if not _B64_CANDIDATE_RE.match(cand):
            print(f"layer {layer}: 非 base64 候选，停止剥离")
            break
        try:
            peeled = base64.b64decode(cand, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            print(f"layer {layer}: base64 解码失败，停止剥离")
            break
        print(f"layer {layer}: len={len(peeled)} sha={_sha8(peeled)} "
              f"frag={redact_fragment(peeled)}")
        if len(peeled) >= 256 * 1024:
            print("达到 256KB 解码输出上限，停止")
            break
        data = peeled
    return 0


# ══════════════════════ main ══════════════════════

def _err(code: str, field: str, message: str, hint: str = "") -> int:
    json.dump({"ok": False, "error_code": code, "field": field,
               "message": message, "hint": hint},
              sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 3


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="entry.py",
        description="AI 内容安检：PITAX 确定性检测提示注入/隐形字符/编码载荷/AI 配置后门。")
    ap.add_argument("--text", help="直接传入待检文本（短文本 <8KB）")
    ap.add_argument("--file", help="待检文件路径（- 表示读 stdin）")
    ap.add_argument("--dir", dest="dir_path", help="待检目录/仓库（递归只读扫描）")
    ap.add_argument("--mode", choices=["auto", "config"], default="auto",
                    help="config=仅审计 AI 配置文件（.cursor/rules、CLAUDE.md 等）")
    ap.add_argument("--format", choices=["json", "markdown"], default="json")
    ap.add_argument("--min-severity", choices=["critical", "high", "medium"])
    ap.add_argument("--fail-on", choices=["critical", "high", "medium"],
                    help="发现该级别及以上命中时退出码 1（CI 用）")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    ap.add_argument("--out", help="报告输出目录（默认：仅 findings>10 时写系统临时目录）")
    ap.add_argument("--sarif", help="导出 SARIF 2.1.0 到指定文件（仓库模式用）")
    ap.add_argument("--decode", help=argparse.SUPPRESS)
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--version", action="version",
                    version=f"{SKILL_NAME} {SKILL_VERSION}")
    args = ap.parse_args(argv)

    if args.self_check:
        return self_check()
    if args.decode is not None:
        return decode_review(args.decode)

    # session JSONL 遥测锚：每次执行在 stderr 留稳定标记，供触发率统计
    print(f"[{SKILL_NAME}] v{SKILL_VERSION} engine=pitax-{PITAX_VERSION}",
          file=sys.stderr)

    inputs = [x for x in (args.text, args.file, args.dir_path) if x]
    if len(inputs) != 1:
        return _err("INVALID_ARGUMENT", "text|file|dir",
                    "必须且只能提供 --text / --file / --dir 之一",
                    "长文本请写入临时文件后用 --file，勿走命令行参数")

    started = time.monotonic()
    findings: list[dict] = []
    coverage: dict = {}
    errors: list[str] = []
    try:
        if args.text is not None:
            findings, coverage, errors = collect_text(args.text)
        elif args.file is not None:
            if args.file == "-":
                findings, coverage, errors = collect_text(read_stdin_text())
            else:
                fpath = Path(args.file).expanduser().resolve()
                if not fpath.is_file():
                    return _err("NOT_FOUND", "file", f"文件不存在：{fpath}")
                findings = scan_file(fpath.name, _decode_bytes(_read_file_bytes(fpath)))
                coverage = {"root": str(fpath), "files_scanned": 1, "files_skipped": 0,
                            "sensitive_skipped": [], "bytes_scanned": fpath.stat().st_size,
                            "truncated": False, "limits": [
                                "确定性层仅覆盖 PITAX 规则集；语义改写类攻击不在本层覆盖内"]}
        else:
            root = guard_root(args.dir_path)
            if not root.exists():
                return _err("NOT_FOUND", "dir", f"目录不存在：{root}")
            files_map, coverage, errors = collect_dir(
                root, args.max_files, args.max_bytes, args.max_depth,
                args.timeout, config_only=(args.mode == "config"))
            findings = scan_repo(files_map)
    except ValueError as exc:
        return _err("GUARD_REJECTED", "path", str(exc),
                    "系统目录/敏感路径/超大文件被防护策略拒绝")
    except (PermissionError, OSError) as exc:
        return _err("RUNTIME_ERROR", "path", f"{type(exc).__name__}: {exc}")

    if args.min_severity:
        floor = _SEVERITY_RANK[args.min_severity]
        findings = [f for f in findings if _SEVERITY_RANK.get(
            str(f.get("severity", "info")).lower(), 4) <= floor]

    agg = aggregate(findings, coverage, errors)
    report_paths = None
    if findings and (len(findings) > 10 or args.out):
        report_paths = write_reports(findings, agg, coverage,
                                     Path(args.out) if args.out else None)
    envelope = build_envelope(findings, agg, coverage, report_paths,
                              int((time.monotonic() - started) * 1000))
    if args.sarif:
        Path(args.sarif).write_text(
            json.dumps(build_sarif(findings, SKILL_NAME, SKILL_VERSION),
                       ensure_ascii=False, indent=2), encoding="utf-8")
        envelope["sarif_path"] = str(Path(args.sarif))

    if args.format == "markdown":
        print(f"## {_risk_word(agg['verdict'])}（{agg['verdict']}）")
        print(envelope["summary"])
        print()
        for r in envelope["top_findings"]:
            print(f"- [{r['severity']}] {r['title']} `{r['file']}:{r['line']}`")
            print(f"  - {r['evidence_redacted']}")
        print()
        print("零命中仅代表当前规则集未发现命中，不代表内容绝对安全。")
    else:
        json.dump(envelope, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")

    if args.fail_on and any(_SEVERITY_RANK.get(
            str(f.get("severity", "info")).lower(), 4) <= _SEVERITY_RANK[args.fail_on]
            for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
