from __future__ import annotations

import math
import re
from typing import Optional

from security_scanner.config import config

SUSPICIOUS_EXECUTION_TERMS: list[str] = config.suspicious_execution_terms
SUSPICIOUS_URL_PATTERNS: list[str] = config.url_patterns
ENTROPY_THRESHOLD: float = config.entropy_threshold

HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039A": "K", "\u039C": "M",
    "\u039D": "N", "\u039F": "O", "\u03A1": "P", "\u03A4": "T",
    "\u03A5": "Y", "\u03A7": "X", "\u03B1": "a", "\u03B5": "e",
    "\u03BF": "o", "\u03C1": "p", "\u03C3": "o", "\u03C5": "u",
    "\u03C7": "x",
    "\u00E0": "a", "\u00E1": "a", "\u00E2": "a", "\u00E3": "a",
    "\u00E4": "a", "\u00E5": "a", "\u00E8": "e", "\u00E9": "e",
    "\u00EA": "e", "\u00EB": "e", "\u00EC": "i", "\u00ED": "i",
    "\u00EE": "i", "\u00EF": "i", "\u00F2": "o", "\u00F3": "o",
    "\u00F4": "o", "\u00F5": "o", "\u00F6": "o", "\u00F9": "u",
    "\u00FA": "u", "\u00FB": "u", "\u00FC": "u", "\u0101": "a",
    "\u0103": "a", "\u0105": "a", "\u0113": "e", "\u0115": "e",
    "\u0117": "e", "\u0119": "e", "\u012B": "i", "\u014D": "o",
    "\u014F": "o", "\u0151": "o", "\u016B": "u", "\u016D": "u",
    "\u016F": "u", "\u0171": "u", "\u01CE": "a", "\u01D0": "i",
    "\u01D2": "o", "\u01D4": "u",
    "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d",
    "\uFF45": "e", "\uFF46": "f", "\uFF47": "g", "\uFF48": "h",
    "\uFF49": "i", "\uFF4A": "j", "\uFF4B": "k", "\uFF4C": "l",
    "\uFF4D": "m", "\uFF4E": "n", "\uFF4F": "o", "\uFF50": "p",
    "\uFF51": "q", "\uFF52": "r", "\uFF53": "s", "\uFF54": "t",
    "\uFF55": "u", "\uFF56": "v", "\uFF57": "w", "\uFF58": "x",
    "\uFF59": "y", "\uFF5A": "z",
    "\uA723": "f",
    "\u02B0": "h", "\u02B2": "j", "\u02B3": "r", "\u02B7": "w",
    "\u02B8": "y",
}


def _decode_hex_sequence(match: re.Match) -> str:
    try:
        hex_str = match.group(0)
        parts = re.findall(r"\\x([0-9a-fA-F]{2})", hex_str)
        decoded_bytes = bytes(int(h, 16) for h in parts)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        return decoded if decoded.isprintable() else hex_str
    except Exception:
        return match.group(0)


def normalize_text(text: str) -> str:
    text = re.sub(r"(?:\\x[0-9a-fA-F]{2})+", _decode_hex_sequence, text)
    text = re.sub(r"\\(.)", r"\1", text)
    text = re.sub(r"(?<=\w)['\"](?=\w)", "", text)
    text = re.sub(r"\$\(([^)]*)\)", r" \1 ", text)
    text = text.replace("`", " ")
    return text


def normalize_homoglyphs(text: str) -> str:
    result = []
    for char in text:
        result.append(HOMOGLYPH_MAP.get(char, char))
    return "".join(result)


def normalize_text_recursive(text: str, max_iterations: int = 5) -> str:
    previous = ""
    current = text
    iterations = 0
    while current != previous and iterations < max_iterations:
        previous = current
        current = normalize_text(previous)
        current = normalize_homoglyphs(current)
        iterations += 1
    return current


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    text = text.strip()
    if len(text) < 10:
        return 0.0
    entropy = 0.0
    for char in set(text):
        prob = text.count(char) / len(text)
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def max_line_entropy(text: str) -> float:
    max_e = 0.0
    for line in text.split("\n"):
        e = calculate_shannon_entropy(line)
        if e > max_e:
            max_e = e
    return max_e


def find_high_entropy_lines(text: str, threshold: float = 6.0) -> list[str]:
    high_lines: list[str] = []
    for line in text.split("\n"):
        line = line.strip()
        if len(line) < 20:
            continue
        e = calculate_shannon_entropy(line)
        if e > threshold:
            high_lines.append(f"line={line[:60]}[...] entropy={e:.2f}")
    return high_lines


def find_suspicious_terms_in_text(text: str) -> list[str]:
    normalized = normalize_text_recursive(text)
    found_terms = [term for term in SUSPICIOUS_EXECUTION_TERMS if term in normalized]
    found_urls = [pattern for pattern in SUSPICIOUS_URL_PATTERNS if re.search(pattern, text)]
    extra = find_high_entropy_lines(text)
    return found_terms + found_urls + extra


def text_contains_base64_decode_pipeline(text: str) -> bool:
    has_base64_decode = bool(re.search(r"base64\s*(-d|--decode|/d)", text, re.IGNORECASE))
    has_pipe_to_shell = bool(re.search(r"\|[\s]*(bash|sh|zsh|fish)", text, re.IGNORECASE))
    has_echo_base64 = bool(
        re.search(r"echo\s+[\"'`]?[A-Za-z0-9+/=]{20,}[\"'`]?\s*\|", text, re.IGNORECASE)
    )
    if has_base64_decode and has_pipe_to_shell:
        return True
    if has_echo_base64 and has_pipe_to_shell:
        return True
    return has_base64_decode


def detect_js_join_obfuscation(text: str) -> list[str]:
    patterns: list[str] = []
    if "join(" in text and re.search(r"""['"][\w-]+['"][,\s]*['"][\w-]+['"]""", text):
        match = re.search(
            r"""\['?([^\]]+?)'?\]\.\s*join\s*\(\s*['""]\s*['""]\s*\)""", text
        )
        if match:
            patterns.append(f"Array.join('') detected: [{match.group(1)[:80]}]")
    if "fromCharCode" in text:
        patterns.append("String.fromCharCode detected")
    return patterns


def detect_high_entropy_content(text: str) -> bool:
    return calculate_shannon_entropy(text) > ENTROPY_THRESHOLD
