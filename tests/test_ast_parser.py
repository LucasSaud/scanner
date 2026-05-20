from security_scanner.parsers.ast_parser import analyze_python_code_ast


def test_python_ast_eval():
    findings = analyze_python_code_ast("eval('print(1)')")
    assert len(findings) > 0
    assert "eval" in findings[0]


def test_python_ast_subprocess():
    findings = analyze_python_code_ast("import subprocess; subprocess.Popen(['ls'])")
    assert len(findings) > 0
    assert any("subprocess.Popen" in f for f in findings)


def test_python_ast_suspicious_import():
    findings = analyze_python_code_ast("import marshal; marshal.loads(b'...')")
    assert len(findings) > 0
    assert any("marshal" in f for f in findings)


def test_python_ast_safe_code():
    findings = analyze_python_code_ast("x = 1 + 2; print(x)")
    assert len(findings) == 0


def test_python_ast_syntax_error():
    findings = analyze_python_code_ast("this is not valid python @@@")
    assert len(findings) == 0
