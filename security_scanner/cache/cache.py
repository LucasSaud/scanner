from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from security_scanner.utils.hash_utils import file_hash

CACHE_DIR = Path.home() / ".scanner"
CACHE_FILE = CACHE_DIR / "scan_cache.json"
DEFAULT_TTL_HOURS = 24


@dataclass
class CacheEntry:
    mtime: float
    content_hash: str
    findings_hash: str
    cached_at: float

    def is_expired(self, ttl_hours: float = DEFAULT_TTL_HOURS) -> bool:
        return (time.time() - self.cached_at) > (ttl_hours * 3600)

    def is_stale(self, file_path: Path) -> bool:
        try:
            stat = file_path.stat()
            current_mtime = stat.st_mtime
            if current_mtime != self.mtime:
                return True
            current_hash = file_hash(file_path)
            if current_hash is not None and current_hash != self.content_hash:
                return True
        except OSError:
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "mtime": self.mtime,
            "content_hash": self.content_hash,
            "findings_hash": self.findings_hash,
            "cached_at": self.cached_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CacheEntry:
        return cls(
            mtime=float(data.get("mtime", 0)),
            content_hash=str(data.get("content_hash", "")),
            findings_hash=str(data.get("findings_hash", "")),
            cached_at=float(data.get("cached_at", 0)),
        )


class ScanCache:
    def __init__(self, cache_path: Optional[Path] = None, ttl_hours: float = DEFAULT_TTL_HOURS):
        self._cache_path = cache_path or CACHE_FILE
        self._ttl_hours = ttl_hours
        self._lock = threading.Lock()
        self._cache: dict[str, CacheEntry] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            if self._cache_path.exists():
                raw = self._cache_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                for path_key, entry_data in data.items():
                    entry = CacheEntry.from_dict(entry_data)
                    if not entry.is_expired(self._ttl_hours):
                        self._cache[path_key] = entry
        except Exception:
            self._cache = {}

    def _save(self) -> None:
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            data = {k: v.to_dict() for k, v in self._cache.items()}
            self._cache_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
            self._dirty = False
        except Exception:
            pass

    def flush(self) -> None:
        with self._lock:
            if self._dirty:
                self._save()

    def _path_key(self, file_path: Path) -> str:
        try:
            return str(file_path.resolve())
        except Exception:
            return str(file_path.absolute())

    def is_cached(self, file_path: Path, mtime: Optional[float] = None) -> bool:
        key = self._path_key(file_path)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.is_expired(self._ttl_hours):
                del self._cache[key]
                self._dirty = True
                return False
            # Copy entry under lock to avoid TOCTOU
            entry_copy = CacheEntry(
                mtime=entry.mtime,
                content_hash=entry.content_hash,
                findings_hash=entry.findings_hash,
                cached_at=entry.cached_at,
            )
        return not entry_copy.is_stale(file_path)

    def mark_cached(self, file_path: Path, mtime: float,
                    content_hash: str, findings_hash: str) -> None:
        entry = CacheEntry(
            mtime=mtime,
            content_hash=content_hash,
            findings_hash=findings_hash,
            cached_at=time.time(),
        )
        key = self._path_key(file_path)
        with self._lock:
            self._cache[key] = entry
            self._save()

    def get_findings_hash(self, file_path: Path) -> Optional[str]:
        key = self._path_key(file_path)
        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.is_expired(self._ttl_hours):
                return entry.findings_hash
        return None

    def invalidate(self, file_path: Path) -> None:
        key = self._path_key(file_path)
        with self._lock:
            if self._cache.pop(key, None) is not None:
                self._dirty = True
            self._save()

    def invalidate_prefix(self, prefix: Path) -> int:
        prefix_str = str(prefix.resolve())
        keys_to_remove: list[str] = []
        with self._lock:
            for key in self._cache:
                if key.startswith(prefix_str):
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del self._cache[key]
            if keys_to_remove:
                self._save()
        return len(keys_to_remove)

    def clear_all(self) -> None:
        with self._lock:
            self._cache.clear()
            self._save()

    def get_stats(self) -> dict:
        with self._lock:
            total = len(self._cache)
            now = time.time()
            expired = sum(1 for e in self._cache.values()
                          if e.is_expired(self._ttl_hours))
            ages = [now - e.cached_at for e in self._cache.values()]
            avg_age = sum(ages) / len(ages) if ages else 0.0
            return {
                "total_entries": total,
                "expired_entries": expired,
                "avg_age_seconds": round(avg_age, 1),
                "cache_path": str(self._cache_path),
                "ttl_hours": self._ttl_hours,
            }


scan_cache = ScanCache()
