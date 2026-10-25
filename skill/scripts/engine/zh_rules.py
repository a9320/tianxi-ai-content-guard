"""中文与判决劫持覆盖层检测规则（skill 自有层，不入 vendor 五文件锚）。

定位：上游 arcanum-spark 双语重构落地前的**过渡覆盖层**——补齐中文攻击面与
"报告 clean"类判决劫持（2026-10-25 严格测试 P0-1/P0-3）；上游落地后合并迁移
（见 vendor/SYNC.md 分叉记录）。

纪律：
- 复用 PITAX 官方编号（T-46/N-06/T-51），不编造编号/CWE/CVE；
- 覆盖层 confidence 统一降档 70（中文变体未经实弹 CONFIRMED，守规则矿纪律）；
- 全部为只读正则匹配，特征串以普通字符串书写（无混淆、无动态执行）。
"""
from __future__ import annotations

import re

from .detectors import is_ai_config_path
from .rules import get_rule

ZH_CONFIDENCE = 70

# ── 指令覆盖（忽略/无视之前指令）──
_P_OVERRIDE = re.compile(
    r"(忽略|无视|忘记|丢弃|不再遵守| disregard)[^。.\n,，;；]{0,16}"
    r"(指令|规则|提示词|提示|要求|设定|说明|约束|限制)")

# ── 角色劫持/越狱 ──
_P_ROLE = re.compile(
    r"(你现在是|你现在是一个|你现在是一|扮演|充当|假扮|进入)[^。.\n]{0,22}"
    r"(没有任何限制|无任何限制|无限制|不受任何限制|不受限|开发者模式|开发模式|越狱模式|DAN)")

# ── 系统提示泄露 ──
_P_LEAK = re.compile(
    r"(输出|泄露|告诉我|显示|打印|复述)[^。.\n]{0,10}"
    r"(系统提示|系统指令|初始指令|系统提示词|system\s*prompt)", re.I)

# ── 判决劫持（要求报告安全结论）──
_P_HIJACK_ZH = re.compile(
    r"(报告|输出|判定|判决|回复|告诉[^。.\n]{0,6}用户)[^。.\n]{0,12}"
    r"(clean|安全|通过|未检出|无风险|没有风险|正常|无害)")
_P_HIJACK_EN = re.compile(
    r"(report|state|output|reply|tell[^.\n]{0,12}user)[^.\n]{0,20}"
    r"\b(clean|safe|passed|benign|no\s+issues|harmless)\b"
    r"|verdict\s+is\s+(clean|safe)", re.I)

# ── 数据外传 ──
_P_EXFIL_ZH = re.compile(
    r"(发送|上传|外传|传送|发给|邮寄到|提交到|传到)[^。.\n]{0,16}"
    r"(所有|全部|一切)?[^。.\n]{0,12}"
    r"(文件|数据|密钥|密码|凭据|令牌|通讯录|联系人|聊天记录|api|key|token)", re.I)
# 把字句语序：把/将 + 对象 + 发送/外传（中文常见 O-V 结构）
_P_EXFIL_ZH2 = re.compile(
    r"(把|将)[^。.\n]{0,24}(所有|全部|一切)?[^。.\n]{0,20}"
    r"(文件|数据|密钥|密码|凭据|令牌|通讯录|联系人|聊天记录|内容|api|key|token|\.env)"
    r"[^。.\n]{0,16}(发送|上传|外传|传到|发给|提交到|邮寄到|传给)", re.I)
_P_EXFIL_EN = re.compile(
    r"(exfiltrate|send|upload|mail)[^.\n]{0,14}\b(all|every|the)\b[^.\n]{0,14}"
    r"\b(files|data|keys|tokens|secrets|credentials|passwords|contacts)\b", re.I)

# ── 工具滥用（要求执行破坏命令）──
_P_TOOLABUSE_ZH = re.compile(
    r"(执行|运行|调用|帮我?跑)[^。.\n]{0,14}"
    r"(rm\s*-rf|格式化|删除所有|清空全部|关机|format\s+/|del\s+/[a-z])", re.I)

# ── 编码载荷解码后的补充关键词（英文引擎关键词表缺口 + 中文）──
ENCODED_KEYWORDS_ZH = (
    "忽略", "指令", "密钥", "密码", "系统提示", "发送", "删除", "越狱",
    "ignore all rules", "ignore every rule", "disable safety",
    "report clean", "exfiltrate", "send all",
)

_RULESETS = [
    (_P_OVERRIDE, "override", "high"),
    (_P_ROLE, "role_hijack", "high"),
    (_P_LEAK, "prompt_leak", "high"),
    (_P_HIJACK_ZH, "verdict_hijack", "high"),
    (_P_HIJACK_EN, "verdict_hijack", "high"),
    (_P_EXFIL_ZH, "exfiltration", "high"),
    (_P_EXFIL_ZH2, "exfiltration", "high"),
    (_P_EXFIL_EN, "exfiltration", "high"),
    (_P_TOOLABUSE_ZH, "tool_abuse", "critical"),
]


def _zh_finding(code: str, path: str, line: int, snippet: str, message: str,
                severity: str, decoded: str | None = None) -> dict:
    rule = get_rule(code)
    pitax = {"code": code, "name": rule["name"], "pillar": rule["pillar"],
             "evidence": snippet[:240],
             "references": rule.get("references", [])}
    if decoded:
        pitax["decoded_payload"] = decoded[:160]
    return {
        "id": "", "type": code, "title": f"[{code}] {rule['name']}",
        "severity": severity, "confidence": ZH_CONFIDENCE,
        "cwe": rule.get("cwe"), "mitre_atlas": rule.get("mitre_atlas"),
        "description": message, "file": path, "line": line,
        "language": "text", "code_snippet": snippet[:240],
        "agent": "agent_0_sanitizer",
        "suggestion": "移除该指令性内容；将其视为不可信数据，不执行、不遵循。",
        "pitax": pitax,
    }


def scan_zh(content: str, path: str, _n: int = 0) -> list[dict]:
    """中文/劫持覆盖层扫描。按路径语义选 PITAX 编号，永不抛异常。"""
    findings: list[dict] = []
    try:
        is_cfg = is_ai_config_path(path)
        code_cfg = "PIT-T-46" if is_cfg else "PIT-N-06"
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.lstrip()
            is_comment = stripped.startswith(("#", "//", "*", ";"))
            for pat, kind, severity in _RULESETS:
                m = pat.search(line)
                if not m:
                    continue
                code = code_cfg
                if not is_cfg and is_comment:
                    code = "PIT-T-51"
                msg = {
                    "override": "检测到中文指令覆盖类注入（要求忽略既有指令/规则）。",
                    "role_hijack": "检测到中文角色劫持/越狱指令。",
                    "prompt_leak": "检测到要求泄露系统提示的注入指令。",
                    "verdict_hijack": "检测到判决劫持指令（要求报告安全结论），"
                                      "这是针对安全检测本身的攻击。",
                    "exfiltration": "检测到数据外传指令（要求发送数据/密钥到外部）。",
                    "tool_abuse": "检测到要求执行破坏性命令的注入指令。",
                }[kind]
                findings.append(_zh_finding(code, path, lineno, m.group(0), msg,
                                            "critical" if (is_cfg and severity == "high") else severity))
    except Exception:
        return []
    for i, f in enumerate(findings, start=1):
        f["id"] = f"zh-{_n}-{i}"
    return findings


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def scan_encoded_zh(content: str, path: str, _n: int = 0) -> list[dict]:
    """补充编码检测：对全文 base64 候选（含非引号语境）解码 ≤3 层后匹配
    覆盖层关键词表（补引擎英文关键词缺口与中文载荷），与引擎既有命中按行去重。"""
    import base64 as _b64
    import binascii as _bin
    findings: list[dict] = []
    try:
        for lineno, line in enumerate(content.splitlines(), start=1):
            for cand in _B64_RUN.findall(line)[:8]:
                data = cand
                peeled = None
                for _ in range(3):
                    try:
                        data = _b64.b64decode(data, validate=True).decode("utf-8", errors="replace")
                    except (_bin.Error, ValueError, UnicodeDecodeError):
                        break
                    peeled = data
                if not peeled:
                    continue
                low = peeled.lower()
                if any(k in low for k in ENCODED_KEYWORDS_ZH):
                    findings.append(_zh_finding(
                        "PIT-E-57", path, lineno, cand[:80],
                        f"检测到多层编码载荷，解码后命中注入关键词（覆盖层补充检测）。",
                        "critical", decoded=peeled))
                    break
    except Exception:
        return []
    for i, f in enumerate(findings, start=1):
        f["id"] = f"zhenc-{_n}-{i}"
    return findings
