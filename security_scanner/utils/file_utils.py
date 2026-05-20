from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Optional, Tuple


def read_file_safe(file_path: Path, max_size: int = 5 * 1024 * 1024) -> Tuple[bool, str]:
    try:
        if file_path.stat().st_size > max_size:
            return False, ""
        return True, file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False, ""


def get_file_size(file_path: Path) -> int:
    try:
        return file_path.stat().st_size
    except Exception:
        return 0


_BINARY_EXTENSIONS: set[str] = {
    ".exe", ".bin", ".obj", ".o", ".so", ".dll", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".pyc", ".pyo", ".pyd",
    ".DS_Store",
}


def is_binary_file(file_path: Path) -> bool:
    if file_path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
        return b"\0" in chunk
    except Exception:
        return False
