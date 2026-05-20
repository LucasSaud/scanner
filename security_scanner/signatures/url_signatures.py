SUSPICIOUS_URL_PATTERNS: dict[str, dict] = {
    "direct_ip_http": {
        "pattern": r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": "MEDIUM", "score": 50.0,
        "category": "network",
        "description": "URL HTTP com IP direto - possível C2",
    },
    "direct_ip_https": {
        "pattern": r"https://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "severity": "LOW", "score": 35.0,
        "category": "network",
        "description": "URL HTTPS com IP direto",
    },
    "suspicious_port": {
        "pattern": r"https?://[^:]+:(?:4444|5555|6666|7777|8888|9999|1337|31337|4443|8088)",
        "severity": "MEDIUM", "score": 50.0,
        "category": "network",
        "description": "URL com porta suspeita",
    },
    "pastebin_raw": {
        "pattern": r"pastebin\.com/raw/",
        "severity": "HIGH", "score": 70.0,
        "category": "exfiltration",
        "description": "URL raw do Pastebin - possível payload",
    },
    "gist_raw": {
        "pattern": r"gist\.github(?:usercontent)?\.com/[a-zA-Z0-9_-]+/raw/",
        "severity": "HIGH", "score": 70.0,
        "category": "exfiltration",
        "description": "URL raw do GitHub Gist - possível payload",
    },
    "ngrok_url": {
        "pattern": r"https?://[a-zA-Z0-9-]+\.ngrok(?:-free)?\.(?:io|app)",
        "severity": "HIGH", "score": 70.0,
        "category": "tunnel",
        "description": "URL ngrok - possível túnel malicioso",
    },
    "suspicious_tld_download": {
        "pattern": r"https?://[^/\s]+\.(?:tk|ml|ga|cf|gq)/",
        "severity": "MEDIUM", "score": 55.0,
        "category": "network",
        "description": "Download de domínio com TLD suspeito",
    },
    "ipfs_gateway": {
        "pattern": r"https?://(?:ipfs\.io|gateway\.ipfs\.io|cloudflare-ipfs\.com)/ipfs/",
        "severity": "LOW", "score": 30.0,
        "category": "network",
        "description": "URL de gateway IPFS - conteúdo não verificado",
    },
    "raw_githubusercontent": {
        "pattern": r"raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/",
        "severity": "MEDIUM", "score": 40.0,
        "category": "network",
        "description": "URL raw.githubusercontent.com - download remoto",
    },
}
