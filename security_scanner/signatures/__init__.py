from security_scanner.signatures.registry import SignatureRegistry, SignatureMatch
from security_scanner.signatures.ioc_signatures import IOCDatabase, BUILTIN_IOCS
from security_scanner.signatures.regex_signatures import (
    SUSPICIOUS_REGEX_PATTERNS,
    OBFUSCATION_PATTERNS,
    PERSISTENCE_PATTERNS,
    EXFILTRATION_PATTERNS,
)
from security_scanner.signatures.command_signatures import COMMAND_SIGNATURES
from security_scanner.signatures.shell_signatures import SHELL_DANGEROUS_PATTERNS
from security_scanner.signatures.base64_signatures import ENCODING_SIGNATURES
from security_scanner.signatures.obfuscation_signatures import OBFUSCATION_SIGNATURE_PATTERNS
from security_scanner.signatures.url_signatures import SUSPICIOUS_URL_PATTERNS as SUS_URL_PATTERNS

__all__ = [
    "SignatureRegistry", "SignatureMatch",
    "IOCDatabase", "BUILTIN_IOCS",
    "SUSPICIOUS_REGEX_PATTERNS", "OBFUSCATION_PATTERNS",
    "PERSISTENCE_PATTERNS", "EXFILTRATION_PATTERNS",
    "COMMAND_SIGNATURES",
    "SHELL_DANGEROUS_PATTERNS",
    "ENCODING_SIGNATURES",
    "OBFUSCATION_SIGNATURE_PATTERNS",
    "SUS_URL_PATTERNS",
]
