from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IocType(Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"
    TLD = "tld"
    EMAIL = "email"
    WEBHOOK = "webhook"


IOC_SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class IOC:
    ioc_type: IocType
    value: str
    severity: str = "MEDIUM"
    category: str = "general"
    description: str = ""
    source: str = "builtin"
    pattern: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.ioc_type, str):
            self.ioc_type = IocType(self.ioc_type)

    def to_dict(self) -> dict:
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "source": self.source,
            "tags": self.tags,
        }
