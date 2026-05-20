from __future__ import annotations

import ast
from typing import Optional

try:
    import esprima

    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False

PYTHON_DANGEROUS_FUNCTIONS: set[str] = {
    "eval", "exec", "compile", "__import__",
    "marshal.load", "marshal.loads",
    "pickle.load", "pickle.loads",
    "ctypes.CDLL", "ctypes.WinDLL", "ctypes.CDLL",
    "os.system", "os.popen", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve",
    "os.execvp", "os.execvpe", "os.fork", "os.posix_spawn",
    "subprocess.Popen", "subprocess.call", "subprocess.run",
    "subprocess.check_call", "subprocess.check_output",
    "socket.socket", "socket.create_connection",
}

PYTHON_SUSPICIOUS_IMPORTS: set[str] = {
    "marshal", "pickle", "dill", "shelve",
    "ctypes", "subprocess", "socket",
    "telnetlib", "ftplib",
}


def analyze_python_code_ast(python_code: str) -> list[str]:
    findings: list[str] = []
    try:
        tree = ast.parse(python_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute):
                    parts = []
                    current = func
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    name = ".".join(reversed(parts))
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in PYTHON_DANGEROUS_FUNCTIONS:
                    findings.append(f"AST(Python): dangerous call '{name}'")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in PYTHON_SUSPICIOUS_IMPORTS:
                        findings.append(f"AST(Python): suspicious import '{alias.name}'")
            elif isinstance(node, ast.ImportFrom):
                if node.module in PYTHON_SUSPICIOUS_IMPORTS:
                    findings.append(f"AST(Python): suspicious from-import '{node.module}'")
    except SyntaxError:
        pass
    except Exception:
        pass
    return findings


JS_DANGEROUS_PATTERNS: set[str] = {
    "child_process", "exec", "spawn", "eval",
    "Function", "Buffer.from",
}


def analyze_js_code_with_ast(js_code: str) -> list[str]:
    if not HAS_ESPRIMA:
        return []
    findings: list[str] = []
    try:
        ast_tree = esprima.parseScript(js_code)
        stack = [ast_tree]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                node_type = node.get("type", "")
                if node_type == "CallExpression":
                    callee = node.get("callee", {})
                    name = ""
                    if callee.get("type") == "MemberExpression":
                        parts = []
                        obj = callee
                        while obj.get("type") == "MemberExpression":
                            parts.append(obj.get("property", {}).get("name", ""))
                            obj = obj.get("object", {})
                        parts.append(obj.get("name", ""))
                        name = ".".join(reversed(parts))
                    elif callee.get("type") == "Identifier":
                        name = callee.get("name", "")
                    if any(kw in name.lower() for kw in JS_DANGEROUS_PATTERNS):
                        findings.append(f"AST(JS): dangerous call '{name}'")
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(node, list):
                stack.extend(reversed(node))
    except Exception:
        pass
    return findings
