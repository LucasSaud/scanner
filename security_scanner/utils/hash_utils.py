from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional


def file_hash(file_path: Path, algorithm: str = "sha256") -> Optional[str]:
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def text_hash(text: str, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
