from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def parse_toml_file(file_path: Path) -> Optional[dict]:
    try:
        with open(file_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


def parse_toml_content(content: str) -> Optional[dict]:
    try:
        return tomllib.loads(content)
    except Exception:
        return None
