OBFUSCATION_SIGNATURE_PATTERNS: dict[str, dict] = {
    "eval_chain": {
        "pattern": r"eval\s*\(\s*eval\s*\(",
        "severity": "HIGH", "score": 80.0,
        "category": "obfuscation",
        "description": "Eval aninhado - chain de ofuscação",
    },
    "nested_decode": {
        "pattern": r"(?:decode|unescape|fromCharCode)[^)]*\((?:decode|unescape|fromCharCode)",
        "severity": "HIGH", "score": 75.0,
        "category": "obfuscation",
        "description": "Decode aninhado - possível ofuscação multi-camada",
    },
    "reverse_string": {
        "pattern": r"\.split\(['\"]{2}\)\.reverse\(\)\.join\(['\"]{2}\)",
        "severity": "MEDIUM", "score": 55.0,
        "category": "obfuscation",
        "description": "Reversão de string - possível ofuscação",
    },
    "substring_assembly": {
        "pattern": r"\.substr\s*\([0-9]+,\s*[0-9]+\)\s*\+",
        "severity": "LOW", "score": 35.0,
        "category": "obfuscation",
        "description": "Montagem de string via substr - possível ofuscação",
    },
    "concat_assembly": {
        "pattern": r"['\"][\w]{1,3}['\"]\s*\+\s*['\"][\w]{1,3}['\"]\s*\+\s*['\"][\w]{1,3}['\"]",
        "severity": "LOW", "score": 30.0,
        "category": "obfuscation",
        "description": "Concatenação de pequenas strings - possível ofuscação",
    },
    "invisible_chars": {
        "pattern": r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff]",
        "severity": "MEDIUM", "score": 50.0,
        "category": "obfuscation",
        "description": "Caracteres invisíveis Unicode - possível ofuscação",
    },
    "homoglyph_domain": {
        "pattern": r"[аеорсухАВЕКМНОРСТУХ]",
        "severity": "LOW", "score": 30.0,
        "category": "obfuscation",
        "description": "Possível homoglifo Cyrillic em texto (ofuscação de domínio)",
    },
    "long_entropy_string": {
        "pattern": None,
        "severity": "MEDIUM", "score": 45.0,
        "category": "obfuscation",
        "description": "String de alta entropia - possível payload ofuscado",
    },
    "comment_obfuscation": {
        "pattern": r"/\*[*/]{2,}.*?\*/",
        "severity": "LOW", "score": 20.0,
        "category": "obfuscation",
        "description": "Comentário incomum - possível ofuscação",
    },
    "excessive_nesting": {
        "pattern": r"(?:\(\(\(|\)\)\)|\[\{\[|}\]\])",
        "severity": "LOW", "score": 25.0,
        "category": "obfuscation",
        "description": "Aninhamento excessivo - possível ofuscação",
    },
    "js_fuck_style": {
        "pattern": r"\!\[\]\+\!\[\]",
        "severity": "MEDIUM", "score": 55.0,
        "category": "obfuscation",
        "description": "Padrão JSFuck - ofuscação JavaScript",
    },
    "webpack_obfuscated": {
        "pattern": r"__webpack_require__\([^)]+\)\[['\"]\w{3,6}['\"]\]\s*\(",
        "severity": "MEDIUM", "score": 40.0,
        "category": "obfuscation",
        "description": "Webpack require ofuscado",
    },
}
