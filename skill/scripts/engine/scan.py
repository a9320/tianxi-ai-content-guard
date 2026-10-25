"""PITAX 扫描路由层 — 复刻自 arcanum-spark codeark/tools/pitax_scan.py@168f660 的
scan_file/scan_repo 分流逻辑，剥离 Strands 依赖（skill 包零第三方依赖铁律）。

分流规则（与管线 agent0 同源，保证 12 命中锚可比）：
  - is_ai_config_path(path)  → 只跑 PIT-T-46（AI 指令文件后门）
  - is_doc_path(path)        → 只跑 PIT-N-06（文档投毒）
  - 否则                     → 跑其余检测器（PIT-E-23/54/T-51 + 编码 PIT-E-07/14/36/57）

本文件不属于 vendor 锚（ENGINE-SHA256.txt 只锚五个引擎原文件）；
引擎源头改动分流逻辑时，此处需同步（SYNC.md 纪律）。
"""
from __future__ import annotations

from .detectors import (
    detect_ai_config_injection,
    detect_comment_injection,
    detect_doc_injection,
    detect_encoded_payloads,
    detect_invisible_text,
    detect_trojan_source,
    is_ai_config_path,
    is_doc_path,
)

__all__ = ["scan_file", "scan_repo"]


def scan_file(path: str, content: str, _n: int = 0) -> list[dict]:
    """对单个文件跑匹配的 PITAX 检测器，返回 report_dict 列表。永不抛异常。"""
    findings: list = []
    try:
        if is_ai_config_path(path):
            findings = detect_ai_config_injection(content, path)
        elif is_doc_path(path):
            findings = detect_doc_injection(content, path)
        else:
            findings = [
                *detect_invisible_text(content, path),
                *detect_trojan_source(content, path),
                *detect_comment_injection(content, path),
                *detect_encoded_payloads(content, path),
            ]
    except Exception:
        return []
    return [f.to_report_dict(f"pitax-{_n}-{i}") for i, f in enumerate(findings, start=1)]


def scan_repo(files: dict[str, str]) -> list[dict]:
    """对 {路径: 内容} 全量扫描。空列表 = 无命中或全部失败。"""
    all_findings: list[dict] = []
    for _n, (path, content) in enumerate(files.items(), start=1):
        all_findings.extend(scan_file(path, content, _n=_n))
    return all_findings
