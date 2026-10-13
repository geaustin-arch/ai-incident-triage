"""Minimal defense-in-depth redaction for demo telemetry submitted to an LLM."""
from __future__ import annotations

import re

PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"),
    re.compile(r"(?i)((?:['\"]?\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)\b['\"]?)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"),
    re.compile(r"-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)* PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
)


def redact(text: str) -> tuple[str, int]:
    count = 0
    for index, pattern in enumerate(PATTERNS):
        replacement = r"\1[REDACTED]" if index < 2 else "[REDACTED]" if index < 7 else "[EMAIL]"
        text, hits = pattern.subn(replacement, text)
        count += hits
    return text, count


def prepare_lines(lines: list[str]) -> tuple[dict[str, str], int]:
    prepared: dict[str, str] = {}
    redactions = 0
    for index, line in enumerate(lines, start=1):
        safe, count = redact(line[:1000])
        prepared[f"log-{index:02d}"] = safe
        redactions += count
    return prepared, redactions
