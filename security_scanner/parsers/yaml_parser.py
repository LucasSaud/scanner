from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_yaml_file(file_path: Path) -> Optional[Any]:
    if not HAS_YAML:
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def parse_yaml_content(content: str) -> Optional[Any]:
    if not HAS_YAML:
        return None
    try:
        return yaml.safe_load(content)
    except Exception:
        return None
