from __future__ import annotations

from pathlib import Path
from typing import Optional


FILE_TYPE_CATEGORIES: dict[str, str] = {
    ".json": "config",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".py": "source",
    ".js": "source",
    ".ts": "source",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "shell",
    ".rb": "source",
    ".pl": "source",
    ".php": "source",
    ".rs": "source",
    ".go": "source",
    ".java": "source",
    ".md": "docs",
}

PATH_SENSITIVITY: dict[str, float] = {
    ".git/hooks/": 95.0,
    ".vscode/": 80.0,
    ".devcontainer/": 80.0,
    ".github/workflows/": 85.0,
    ".husky/": 80.0,
    ".env": 70.0,
    "node_modules/": 20.0,
    ".venv/": 20.0,
    "site-packages/": 30.0,
    "etc/": 60.0,
}


class ContextualAnalyzer:
    @staticmethod
    def analyze_file_path(file_path: Path) -> dict:
        path_str = str(file_path)
        context = {
            "is_in_dotdir": any(p.startswith(".") for p in file_path.parts),
            "extension": file_path.suffix.lower(),
            "file_type": FILE_TYPE_CATEGORIES.get(file_path.suffix.lower(), "unknown"),
            "sensitivity": 30.0,
            "is_hidden": file_path.name.startswith("."),
            "in_git_hooks": ".git/hooks/" in path_str,
            "in_vscode": ".vscode/" in path_str,
            "in_github_actions": ".github/workflows/" in path_str,
            "in_devcontainer": ".devcontainer/" in path_str,
            "in_node_modules": "node_modules/" in path_str,
            "is_config": file_path.suffix.lower() in (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"),
            "is_script": file_path.suffix.lower() in (".sh", ".py", ".js", ".rb", ".pl", ".php"),
        }

        for path_pattern, sensitivity in PATH_SENSITIVITY.items():
            if path_pattern in path_str:
                context["sensitivity"] = max(context["sensitivity"], sensitivity)

        return context

    @staticmethod
    def analyze_auto_execution(context: str) -> dict:
        auto_keywords = {
            "postinstall": "npm_postinstall", "preinstall": "npm_preinstall",
            "prepare": "npm_prepare",
            "postCreateCommand": "devcontainer_post_create",
            "postStartCommand": "devcontainer_post_start",
            "postAttachCommand": "devcontainer_post_attach",
            "initializeCommand": "devcontainer_init",
            "postCheckout": "git_post_checkout",
            "postMerge": "git_post_merge",
            "prePush": "git_pre_push",
            "preCommit": "git_pre_commit",
            "runOn": "vscode_run_on",
            "folderOpen": "vscode_folder_open",
            "postinstall": "npm_postinstall",
        }
        detected = []
        for keyword, name in auto_keywords.items():
            if keyword.lower() in context.lower():
                detected.append(name)
        return {
            "has_auto_execution": len(detected) > 0,
            "auto_execution_types": detected,
        }

    @staticmethod
    def estimate_risk_boost(context: dict, signal_count: int) -> float:
        boost = 0.0
        if context.get("in_git_hooks"):
            boost += 15.0
        if context.get("in_vscode"):
            boost += 10.0
        if context.get("in_github_actions"):
            boost += 15.0
        if context.get("in_devcontainer"):
            boost += 10.0
        if signal_count > 2:
            boost += 5.0 * (signal_count - 2)
        return min(boost, 40.0)
