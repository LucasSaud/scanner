from security_scanner.utils.text_utils import (
    normalize_text,
    normalize_homoglyphs,
    normalize_text_recursive,
    calculate_shannon_entropy,
    text_contains_base64_decode_pipeline,
    detect_js_join_obfuscation,
    detect_high_entropy_content,
    find_high_entropy_lines,
)


def test_normalize_backslash_escaping():
    assert normalize_text(r"c\url") == "curl"


def test_normalize_quotes_between():
    assert normalize_text("w'g'et") == "wget"


def test_normalize_subshell():
    assert "curl" in normalize_text("$(curl http://x.x)")


def test_normalize_backticks():
    assert "curl" in normalize_text("`curl`")


def test_normalize_hex():
    result = normalize_text(r"\x68\x74\x74\x70://x.x")
    assert "http://x.x" in result


def test_homoglyphs_cyrillic():
    assert normalize_homoglyphs("\u0441url") == "curl"


def test_recursive_normalize():
    result = normalize_text_recursive(r"c\ur\x6cl")
    assert "curl" in result


def test_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0


def test_shannon_entropy_short():
    assert calculate_shannon_entropy("abc") == 0.0


def test_shannon_entropy_base64():
    e = calculate_shannon_entropy("dGhpcyBpcyBhIHRlc3Q=")
    assert e > 3.0


def test_base64_decode_pipeline():
    assert text_contains_base64_decode_pipeline("echo dGVzdA== | base64 -d | bash")


def test_js_join_detection():
    result = detect_js_join_obfuscation("['b','a','s','h'].join('')")
    assert len(result) > 0


def test_js_fromcharcode():
    result = detect_js_join_obfuscation("String.fromCharCode(98,97,115,104)")
    assert len(result) > 0


def test_high_entropy_content():
    # A long base64 string should have entropy > 4.5
    b64 = "dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBlbnRyb3B5IHdpdGggbW9yZSBjaGFycyB0byB0ZXN0IHNvbWUgdGhpbmc="
    assert detect_high_entropy_content(b64) is True


def test_find_high_entropy_lines():
    b64 = "dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBlbnRyb3B5IHdpdGggbW9yZSBjaGFycyB0byB0ZXN0IHNvbWUgdGhpbmc="
    text = f"normal line\n{b64}\nanother line"
    lines = find_high_entropy_lines(text, threshold=4.5)
    assert len(lines) > 0
