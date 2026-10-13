"""Minimal defense-in-depth redaction for demo telemetry submitted to an LLM."""
from __future__ import annotations

import re

PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"),
    re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
)


def redact(text: str) -> tuple[str, int]:
    count = 0
    for index, pattern in enumerate(PATTERNS):
        replacement = r"\1[REDACTED]" if index < 2 else "[EMAIL]"
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
