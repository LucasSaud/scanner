from pathlib import Path

from security_scanner.parsers.jsonc import strip_jsonc_comments, parse_jsonc_file


def test_strip_single_line_comments():
    raw = '{"key": "value", // inline comment\n"key2": "value2"}'
    result = strip_jsonc_comments(raw)
    assert "//" not in result
    assert '"key": "value"' in result


def test_strip_multi_line_comments():
    raw = '{"key": "value" /* block comment */, "key2": "value2"}'
    result = strip_jsonc_comments(raw)
    assert "/*" not in result
    assert '"key": "value"' in result


def test_strip_comments_does_not_break_string():
    raw = '{"url": "http://example.com"}'
    result = strip_jsonc_comments(raw)
    assert "http://example.com" in result


def test_strip_comments_with_nested_string():
    raw = '{"regex": "/test/i // not a comment"}'
    # The // inside a string should NOT be stripped
    result = strip_jsonc_comments(raw)
    assert "not a comment" in result
