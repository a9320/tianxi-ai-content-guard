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

from .detectors import _ENCODED_TARGET_RE, is_ai_config_path
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
    r"(输出|泄露|告诉我|显示|打印|复述|reveal)[^。.\n]{0,10}"
    r"(系统提示|系统指令|初始指令|系统提示词|system\s*prompt)", re.I)

# ── 判决劫持：要求结论框架（祈使/判决词），排除疑问（是否/吗）与
#    陈述性汇报（"报告正常/报告未检出"是描述系统而非命令检测者）──
_P_HIJACK_ZH = re.compile(
    r"(?:(?:请|务必|必须|立即|要)\s*)?"
    r"(?:报告|输出|回复|告诉[^。.\n]{0,6}用户)(?![^。.\n]{0,4}(?:已|了))[^。.\n]{0,10}"
    r"(?<!是否)(?<!否)(?<!未检出)(?<!无)(?<!非)(?:clean|安全|通过)"
    r"|(?:判决|判定|结论|verdict)[^。.\n]{0,6}(?:为|是|:|：)\s*(?:clean|安全|通过|未检出)")
_P_HIJACK_EN = re.compile(
    r"(?:^|[.!?]\s+|;\s*|please\s+|now\s+)"
    r"(?:report|state|output|reply|tell[^.\n]{0,12}user)"
    r"(?!\s+(?:whether|if|says|said|is|was|the\s+results))[^.\n]{0,20}"
    r"\b(clean|safe|passed|benign|no\s+issues|harmless)\b"
    r"|verdict\s+is\s+(clean|safe)", re.I | re.M)

# ── 数据外传：敏感对象 ×（外部目的地 或 全量词）双条件，普通办公收发不命中 ──
_SENSITIVE_OBJ = (r"密钥|密码|凭据|令牌|通讯录|联系人|聊天记录|api[\s_-]?key|token|\.env|数据库备份")
_EXTERNAL_DEST = (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|https?://|外部|远程|攻击者|attacker|陌生")
_P_EXFIL_ZH = re.compile(  # V-O：发送 + 全量 + 敏感对象（"发送所有密钥"）
    r"(发送|上传|外传|传送|发给|邮寄到|提交到|传到)[^。.\n]{0,6}"
    r"(所有|全部|一切)[^。.\n]{0,10}"
    rf"(?:{_SENSITIVE_OBJ})", re.I)
_P_EXFIL_ZH2 = re.compile(  # 把字句：敏感对象 + 外部目的地
    rf"(?:把|将)[^。.\n]{{0,24}}(?:{_SENSITIVE_OBJ})[^。.\n]{{0,16}}"
    rf"(?:发送|上传|外传|传到|发给|提交到|邮寄到|传给)[^。.\n]{{0,16}}(?:{_EXTERNAL_DEST})", re.I)
_P_EXFIL_ZH2B = re.compile(  # 把字句：全量 + 敏感对象（任意目的地也高危）
    rf"(?:把|将)[^。.\n]{{0,8}}(?:所有|全部)[^。.\n]{{0,14}}(?:{_SENSITIVE_OBJ})[^。.\n]{{0,16}}"
    r"(?:发送|上传|外传|传到|发给|提交到|邮寄到|传给)", re.I)
_P_EXFIL_ZH3 = re.compile(  # 任意对象 + 外部目的地
    rf"(?:把|将|发送|上传|外传)[^。.\n]{{0,20}}(?:文件|数据|资料)"
    rf"[^。.\n]{{0,14}}(?:{_EXTERNAL_DEST})", re.I)
_P_EXFIL_EN = re.compile(  # all/every + 敏感对象，或任意量 + 外部目的地
    r"(?:exfiltrate|send|upload|mail)[^.\n]{0,14}\b(?:all|every)\b[^.\n]{0,14}"
    r"\b(?:keys?|tokens?|secrets?|credentials?|passwords?|contacts?|api[\s_-]?keys?)\b"
    r"|(?:send|upload|mail|exfiltrate)[^.\n]{0,16}\b(?:files?|data)\b[^.\n]{0,16}"
    r"\b(?:https?://|attacker|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)\b", re.I)

# ── 工具滥用：仅真实破坏命令语法；描述性语句（"清理脚本会删除所有文件"）
#    无祈使前缀不命中；"删除所有临时/缓存文件"类限定词排除 ──
_P_TOOLABUSE_ZH = re.compile(
    r"(?:执行|运行|调用|帮我?跑)[^。.\n]{0,14}"
    r"(rm\s*-rf|mkfs|format\s+/|del\s+/[a-z]|shutdown|格式化[硬盘磁盘系统盘])"
    r"|(?:^|[。.!?\n;；,，]\s*|请|务必|帮我|立即|现在|直接)(?:删除|清空)所有(?!临时|缓存|垃圾|过期|无效)"
    r"(?:文件|数据|目录|记录)"
    r"|(?:执行|运行)[^。.\n]{0,10}(?:(?:rm|mkfs|format|del|shutdown)\b)", re.I)

# ── 编码载荷解码后判定：复用引擎关键词表 + 覆盖层补充（英文短语全集）──
ENCODED_KEYWORDS_ZH = (
    "忽略", "指令", "密钥", "密码", "系统提示", "发送", "删除", "越狱",
)
ENCODED_KEYWORDS_EN = (
    "ignore all previous instructions", "ignore previous instructions",
    "ignore all rules", "ignore every rule", "disregard all previous",
    "disable safety", "report clean", "exfiltrate", "send all",
    "reveal your system prompt", "system prompt", "mail the data",
    "send the data", "api key", "credential", "you are now", "developer mode",
)


def _encoded_hit(peeled: str) -> bool:
    low = peeled.lower()
    if any(k in low for k in ENCODED_KEYWORDS_EN):
        return True
    if any(k in peeled for k in ENCODED_KEYWORDS_ZH):
        return True
    return any(rx.search(peeled) for rx in _ENCODED_TARGET_RE)


_RULESETS = [
    (_P_OVERRIDE, "override", "high"),
    (_P_ROLE, "role_hijack", "high"),
    (_P_LEAK, "prompt_leak", "high"),
    (_P_HIJACK_ZH, "verdict_hijack", "high"),
    (_P_HIJACK_EN, "verdict_hijack", "high"),
    (_P_EXFIL_ZH, "exfiltration", "high"),
    (_P_EXFIL_ZH2, "exfiltration", "high"),
    (_P_EXFIL_ZH2B, "exfiltration", "high"),
    (_P_EXFIL_ZH3, "exfiltration", "high"),
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
    """补充编码检测：对全文 base64 候选（含非引号语境）按实际层数解码后，
    用引擎关键词表+覆盖层补充表判定（修 P0-2 残留：无引号 md/txt 漏检）。
    分级对齐 PITAX 语义：1 层→PIT-E-07 medium；≥2 层→PIT-E-57 critical。"""
    import base64 as _b64
    import binascii as _bin
    findings: list[dict] = []
    try:
        for lineno, line in enumerate(content.splitlines(), start=1):
            for cand in _B64_RUN.findall(line)[:8]:
                data, peeled, layers = cand, None, 0
                for _ in range(5):  # 对齐引擎 _MAX_LAYERS=5（4/5 层无引号载荷也要剥）
                    try:
                        data = _b64.b64decode(data, validate=True).decode(
                            "utf-8", errors="replace")
                    except (_bin.Error, ValueError, UnicodeDecodeError):
                        break
                    peeled, layers = data, layers + 1
                if not peeled or layers == 0 or not _encoded_hit(peeled):
                    continue
                if layers >= 2:
                    code, sev, msg = ("PIT-E-57", "critical",
                                      "检测到多层编码载荷，解码后命中注入关键词（覆盖层补充检测）。")
                else:
                    code, sev, msg = ("PIT-E-07", "medium",
                                      "检测到 base64 编码载荷，解码后命中注入关键词（覆盖层补充检测）。")
                findings.append(_zh_finding(code, path, lineno, cand[:80],
                                            msg, sev, decoded=peeled))
                break
    except Exception:
        return []
    for i, f in enumerate(findings, start=1):
        f["id"] = f"zhenc-{_n}-{i}"
    return findings
