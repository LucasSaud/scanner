from __future__ import annotations

import math
from typing import Optional

from security_scanner.config import config
from security_scanner.utils.text_utils import calculate_shannon_entropy


class EntropyAnalyzer:
    def __init__(self, threshold: float = 0):
        self.threshold = threshold or config.entropy_threshold

    def analyze_line(self, line: str) -> dict:
        entropy = calculate_shannon_entropy(line)
        result = {
            "entropy": round(entropy, 2),
            "length": len(line),
            "flagged": entropy > self.threshold and len(line) >= 10,
            "severity": self._entropy_severity(entropy, len(line)),
        }
        return result

    def analyze_text(self, text: str) -> list[dict]:
        results = []
        for i, line in enumerate(text.split("\n"), 1):
            result = self.analyze_line(line)
            if result["flagged"]:
                result["line"] = i
                result["snippet"] = line[:100]
                results.append(result)
        return results

    def global_entropy(self, text: str) -> float:
        return calculate_shannon_entropy(text)

    def max_line_entropy(self, text: str) -> float:
        max_e = 0.0
        for line in text.split("\n"):
            e = calculate_shannon_entropy(line)
            if e > max_e:
                max_e = e
        return max_e

    def high_entropy_blobs(self, text: str, min_length: int = 30) -> list[dict]:
        blobs = []
        current_blob = ""
        for char in text:
            if char.isalnum() or char in "+/=._-":
                current_blob += char
            else:
                if len(current_blob) >= min_length:
                    e = calculate_shannon_entropy(current_blob)
                    if e > self.threshold:
                        blobs.append({
                            "blob": current_blob[:80],
                            "length": len(current_blob),
                            "entropy": round(e, 2),
                        })
                current_blob = ""
        if len(current_blob) >= min_length:
            e = calculate_shannon_entropy(current_blob)
            if e > self.threshold:
                blobs.append({
                    "blob": current_blob[:80],
                    "length": len(current_blob),
                    "entropy": round(e, 2),
                })
        return blobs

    def estimate_encoding(self, text: str) -> Optional[str]:
        """Estimate what encoding a high-entropy string might be."""
        e = calculate_shannon_entropy(text)
        if e < 4.0:
            return None
        # Check for base64 patterns
        import re
        if re.match(r"^[A-Za-z0-9+/]*={0,2}$", text.strip()):
            return "base64"
        if re.match(r"^[0-9a-fA-F]+$", text.strip()):
            return "hex"
        if set(text.strip()).issubset({"0", "1"}):
            return "binary"
        return "unknown"

    @staticmethod
    def _entropy_severity(entropy: float, length: int) -> str:
        if length < 10:
            return "INFO"
        if entropy > 6.5 and length > 50:
            return "HIGH"
        if entropy > 5.5:
            return "MEDIUM"
        if entropy > 4.5:
            return "LOW"
        return "INFO"
