SUSPICIOUS_REGEX_PATTERNS: dict[str, dict] = {
    "pipe_to_shell": {
        "pattern": r"(curl|wget|fetch)\s+[^\n]*\s*\|\s*(bash|sh|zsh|fish|python|perl)",
        "severity": "CRITICAL", "score": 95.0,
        "category": "supply_chain",
        "description": "Pipe de download direto para shell - execução remota",
    },
    "pipe_python_to_shell": {
        "pattern": r"(curl|wget|fetch)\s+[^\n]*\s*\|\s*python",
        "severity": "CRITICAL", "score": 90.0,
        "category": "supply_chain",
        "description": "Pipe de download para python - execução remota",
    },
    "base64_decode_pipe": {
        "pattern": r"base64\s*(-d|--decode)\s*\|",
        "severity": "HIGH", "score": 80.0,
        "category": "obfuscation",
        "description": "Base64 decode com pipe - possível payload ofuscado",
    },
    "ld_preload": {
        "pattern": r"(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)\s*=",
        "severity": "HIGH", "score": 80.0,
        "category": "persistence",
        "description": "Injeção de biblioteca via LD_PRELOAD",
    },
    "eval_call": {
        "pattern": r"\beval\s*\(",
        "severity": "HIGH", "score": 75.0,
        "category": "command_injection",
        "description": "Chamada eval() - execução dinâmica de código",
    },
    "exec_call": {
        "pattern": r"\bexec\s*\(",
        "severity": "HIGH", "score": 75.0,
        "category": "command_injection",
        "description": "Chamada exec() - execução dinâmica de código",
    },
    "subprocess_spawn": {
        "pattern": r"subprocess\.(?:Popen|call|run|check_call|check_output)\s*\(",
        "severity": "MEDIUM", "score": 60.0,
        "category": "command_injection",
        "description": "Subprocess spawn - possível execução de comando",
    },
    "os_system": {
        "pattern": r"os\.system\s*\(",
        "severity": "HIGH", "score": 75.0,
        "category": "command_injection",
        "description": "os.system() - execução de comando no shell",
    },
    "socket_connect": {
        "pattern": r"socket\.(?:connect|create_connection)\s*\(",
        "severity": "MEDIUM", "score": 50.0,
        "category": "exfiltration",
        "description": "Socket connection - possível comunicação externa",
    },
    "reverse_shell": {
        "pattern": r"(?:bash -i|/dev/tcp/|/dev/udp/|sh -i|exec\s+5<>\s*/dev/tcp)",
        "severity": "CRITICAL", "score": 98.0,
        "category": "backdoor",
        "description": "Indicador de reverse shell",
    },
    "cryptominer": {
        "pattern": r"(?:stratum\+tcp://|pool\.|minexmr|minergate|cryptonight)",
        "severity": "HIGH", "score": 85.0,
        "category": "cryptominer",
        "description": "Indicador de cryptominer",
    },
    "child_process_js": {
        "pattern": r"child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(",
        "severity": "HIGH", "score": 75.0,
        "category": "command_injection",
        "description": "Child process execução em JavaScript",
    },
    "msbuild_exec": {
        "pattern": r"MSBuild\.(?:Execute|Run|Build)",
        "severity": "MEDIUM", "score": 55.0,
        "category": "build_tools",
        "description": "MSBuild execution via script",
    },
    "write_to_sensitive": {
        "pattern": r"(?:writeFile|writeFileSync|WriteAllText)\s*\(.*(?:authorized_keys|id_rsa|\.ssh|shadow|passwd|sudoers)",
        "severity": "CRITICAL", "score": 95.0,
        "category": "persistence",
        "description": "Escrita em arquivo sensível do sistema",
    },
    "chmod_script": {
        "pattern": r"chmod\s+\+x\s+",
        "severity": "LOW", "score": 30.0,
        "category": "general",
        "description": "Arquivo tornado executável",
    },
    "hidden_file": {
        "pattern": r"(?:^\..*|.*\.(?:exe|dll|so|dylib|bat|ps1|vbs))$",
        "severity": "MEDIUM", "score": 45.0,
        "category": "persistence",
        "description": "Arquivo oculto ou executável suspeito",
    },
    "js_code_execution": {
        "pattern": r"Function\s*\(['\"](?:return|new|require|process)",
        "severity": "HIGH", "score": 75.0,
        "category": "command_injection",
        "description": "Criação dinâmica de função em JS - possível execução de código",
    },
}

OBFUSCATION_PATTERNS: dict[str, dict] = {
    "hex_encoding": {
        "pattern": r"(?:\\x[0-9a-fA-F]{2}){4,}",
        "severity": "HIGH", "score": 70.0,
        "category": "obfuscation",
        "description": "Hex encoding de payload detectado",
    },
    "unicode_escape": {
        "pattern": r"\\u[0-9a-fA-F]{4}",
        "severity": "MEDIUM", "score": 55.0,
        "category": "obfuscation",
        "description": "Unicode escape sequences - possível ofuscação",
    },
    "base64_long": {
        "pattern": r"[A-Za-z0-9+/=]{40,}",
        "severity": "LOW", "score": 25.0,
        "category": "obfuscation",
        "description": "Sequência longa de caracteres alfanuméricos - possível base64",
    },
}

PERSISTENCE_PATTERNS: dict[str, dict] = {
    "cron_job": {
        "pattern": r"(?:crontab|@reboot|@daily|@hourly|@weekly)",
        "severity": "HIGH", "score": 80.0,
        "category": "persistence",
        "description": "Agendamento cron - possível persistência",
    },
    "systemd_service": {
        "pattern": r"systemctl\s+(?:enable|start|daemon-reload)",
        "severity": "HIGH", "score": 80.0,
        "category": "persistence",
        "description": "Criação/habilitação de serviço systemd",
    },
    "launchd_plist": {
        "pattern": r"launchctl\s+(?:load|submit)",
        "severity": "HIGH", "score": 75.0,
        "category": "persistence",
        "description": "Registro de launchd - persistência no macOS",
    },
    "rc_local": {
        "pattern": r"(?:/etc/rc\.local|/etc/rc\.d|rc\.local)",
        "severity": "HIGH", "score": 75.0,
        "category": "persistence",
        "description": "Script de inicialização do sistema",
    },
    "profile_d": {
        "pattern": r"(?:/etc/profile\.d/|~/\..*rc|\.bash_profile|\.zprofile)",
        "severity": "HIGH", "score": 70.0,
        "category": "persistence",
        "description": "Shell profile injection - execução automática",
    },
}

EXFILTRATION_PATTERNS: dict[str, dict] = {
    "env_dump": {
        "pattern": r"(?:printenv|env|set)\s*(?:>|>>|\||2>)",
        "severity": "HIGH", "score": 80.0,
        "category": "exfiltration",
        "description": "Dump de variáveis de ambiente para arquivo/pipe",
    },
    "curl_post_data": {
        "pattern": r"curl\s+(?:-X\s+POST|--data|--data-raw|-d\s+[\"'\"](?:@)?)",
        "severity": "HIGH", "score": 75.0,
        "category": "exfiltration",
        "description": "Curl com POST data - possível exfiltração",
    },
    "gpg_encrypt": {
        "pattern": r"gpg\s+(?:-e|--encrypt|--symmetric)",
        "severity": "MEDIUM", "score": 50.0,
        "category": "exfiltration",
        "description": "Criptografia com GPG - possível preparação para exfiltração",
    },
    "pack_files": {
        "pattern": r"(?:tar|zip|7z|rar)\s+(?:-c|-cf|a\s+).*\.(?:tar|zip|7z|rar|gz)",
        "severity": "LOW", "score": 30.0,
        "category": "exfiltration",
        "description": "Empacotamento de arquivos",
    },
}
