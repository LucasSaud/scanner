from __future__ import annotations

import re
from typing import Optional

from security_scanner.models import IOC, IocType


BUILTIN_IOCS: list[IOC] = [
    # Cryptominer pools
    IOC(IocType.URL, "pool.minexmr.com", severity="HIGH", category="cryptominer",
        description="Monero mining pool - possible cryptominer"),
    IOC(IocType.URL, "eth.pool.minergate.com", severity="HIGH", category="cryptominer",
        description="Ethereum mining pool"),
    IOC(IocType.URL, "stratum+tcp://", severity="HIGH", category="cryptominer",
        description="Stratum mining protocol"),
    IOC(IocType.URL, "pool.supportxmr.com", severity="HIGH", category="cryptominer"),
    IOC(IocType.URL, "xmrpool.eu", severity="HIGH", category="cryptominer"),
    IOC(IocType.URL, "nanopool.org", severity="MEDIUM", category="cryptominer"),

    # Data exfiltration endpoints
    IOC(IocType.URL, "webhook.site", severity="MEDIUM", category="exfiltration",
        description="Webhook.site - possible data exfiltration"),
    IOC(IocType.URL, "requestbin.com", severity="MEDIUM", category="exfiltration"),
    IOC(IocType.URL, "hookbin.com", severity="MEDIUM", category="exfiltration"),
    IOC(IocType.URL, "burpcollaborator.net", severity="HIGH", category="exfiltration",
        description="Burp Collaborator - security testing tool, possible exfiltration"),
    IOC(IocType.URL, "interactsh.com", severity="HIGH", category="exfiltration",
        description="Interactsh - out-of-band interaction tool"),

    # DNS exfiltration
    IOC(IocType.URL, "dnslog.cn", severity="MEDIUM", category="exfiltration",
        description="DNSLog.cn - possible DNS exfiltration"),
    IOC(IocType.DOMAIN, "nslookup", severity="MEDIUM", category="exfiltration",
        description="nslookup - possible DNS exfiltration/lateral movement"),

    # Tunneling/Reverse proxy
    IOC(IocType.URL, "ngrok.io", severity="HIGH", category="tunnel",
        description="ngrok tunnel - possible C2 or data exfiltration"),
    IOC(IocType.DOMAIN, "localhost.run", severity="HIGH", category="tunnel"),
    IOC(IocType.DOMAIN, "serveo.net", severity="HIGH", category="tunnel"),
    IOC(IocType.DOMAIN, "localtunnel.me", severity="HIGH", category="tunnel"),
    IOC(IocType.DOMAIN, "bore.pub", severity="MEDIUM", category="tunnel"),

    # Paste sites (code/data sharing, possible exfiltration)
    IOC(IocType.URL, "pastebin.com", severity="MEDIUM", category="exfiltration",
        description="Pastebin - possible data exfiltration"),
    IOC(IocType.URL, "gist.github.com", severity="MEDIUM", category="exfiltration",
        description="GitHub Gist - possible data exfiltration"),

    # Bot/webhook endpoints
    IOC(IocType.URL, "discord.com/api/webhooks", severity="HIGH", category="exfiltration",
        description="Discord webhook - possible data exfiltration"),
    IOC(IocType.URL, "discordapp.com/api/webhooks", severity="HIGH", category="exfiltration"),
    IOC(IocType.URL, "api.telegram.org", severity="HIGH", category="exfiltration",
        description="Telegram Bot API - possible data exfiltration"),
    IOC(IocType.URL, "hooks.slack.com", severity="MEDIUM", category="exfiltration"),

    # Dynamic DNS (malware C2)
    IOC(IocType.DOMAIN, "duckdns.org", severity="LOW", category="dynamic_dns"),
    IOC(IocType.DOMAIN, "noip.org", severity="LOW", category="dynamic_dns"),
    IOC(IocType.DOMAIN, "dyndns.org", severity="LOW", category="dynamic_dns"),
    IOC(IocType.DOMAIN, "afraid.org", severity="LOW", category="dynamic_dns"),

    # IP/Network ranges
    IOC(IocType.IP, "10.", severity="INFO", category="internal_ip",
        description="RFC1918 internal IP"),
    IOC(IocType.IP, "172.16.", severity="INFO", category="internal_ip"),
    IOC(IocType.IP, "192.168.", severity="INFO", category="internal_ip"),
    IOC(IocType.IP, "169.254.", severity="INFO", category="link_local"),

    # Known malware/test domains
    IOC(IocType.DOMAIN, "testing.local", severity="INFO", category="test"),

    # Suspicious TLDs
    IOC(IocType.TLD, ".tk", severity="LOW", category="suspicious_tld",
        description="Free TLD often used by malware"),
    IOC(IocType.TLD, ".ml", severity="LOW", category="suspicious_tld"),
    IOC(IocType.TLD, ".ga", severity="LOW", category="suspicious_tld"),
    IOC(IocType.TLD, ".cf", severity="LOW", category="suspicious_tld"),
    IOC(IocType.TLD, ".gq", severity="LOW", category="suspicious_tld"),
]


class IOCDatabase:
    def __init__(self, iocs: Optional[list[IOC]] = None):
        self._iocs = iocs if iocs is not None else list(BUILTIN_IOCS)

    def add(self, ioc: IOC) -> None:
        self._iocs.append(ioc)

    def match(self, text: str) -> list[IOC]:
        matches: list[IOC] = []
        text_lower = text.lower()
        for ioc in self._iocs:
            if ioc.value.lower() in text_lower:
                matches.append(ioc)
            elif ioc.pattern:
                try:
                    if re.search(ioc.pattern, text, re.IGNORECASE):
                        matches.append(ioc)
                except Exception:
                    pass
        return matches

    def find_in_file(self, content: str) -> list[IOC]:
        return self.match(content)

    def get_by_category(self, category: str) -> list[IOC]:
        return [i for i in self._iocs if i.category == category]

    def get_by_severity(self, severity: str) -> list[IOC]:
        return [i for i in self._iocs if i.severity == severity]
