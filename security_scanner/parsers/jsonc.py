from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def strip_jsonc_comments(raw_content: str) -> str:
    result = []
    i = 0
    inside_string = False
    while i < len(raw_content):
        char = raw_content[i]
        if char == '"' and (i == 0 or raw_content[i - 1] != "\\"):
            inside_string = not inside_string
            result.append(char)
            i += 1
            continue
        if not inside_string:
            if char == "/" and i + 1 < len(raw_content) and raw_content[i + 1] == "/":
                while i < len(raw_content) and raw_content[i] != "\n":
                    i += 1
                continue
            if char == "/" and i + 1 < len(raw_content) and raw_content[i + 1] == "*":
                i += 2
                while i + 1 < len(raw_content) and not (
                    raw_content[i] == "*" and raw_content[i + 1] == "/"
                ):
                    i += 1
                i += 2
                continue
        result.append(char)
        i += 1
    return "".join(result)


def parse_jsonc_file(file_path: Path) -> Optional[dict]:
    try:
        raw = file_path.read_text(encoding="utf-8")
        clean = strip_jsonc_comments(raw)
        return json.loads(clean)
    except Exception:
        return None
