import json
import time
from pathlib import Path

from security_scanner.cache import ScanCache, CacheEntry


class TestCacheEntry:
    def test_defaults(self):
        e = CacheEntry(mtime=100.0, content_hash="abc", findings_hash="def",
                       cached_at=time.time())
        assert e.mtime == 100.0
        assert e.content_hash == "abc"
        assert e.findings_hash == "def"

    def test_is_expired_false(self):
        e = CacheEntry(mtime=100.0, content_hash="a", findings_hash="b",
                       cached_at=time.time())
        assert not e.is_expired(ttl_hours=24)

    def test_is_expired_true(self):
        e = CacheEntry(mtime=100.0, content_hash="a", findings_hash="b",
                       cached_at=time.time() - 999999)
        assert e.is_expired(ttl_hours=1)

    def test_to_dict_roundtrip(self):
        e = CacheEntry(mtime=100.5, content_hash="abc", findings_hash="def",
                       cached_at=200.0)
        d = e.to_dict()
        assert d["mtime"] == 100.5
        assert d["content_hash"] == "abc"
        e2 = CacheEntry.from_dict(d)
        assert e2.mtime == 100.5
        assert e2.content_hash == "abc"
        assert e2.findings_hash == "def"


class TestScanCache:
    def setup_method(self):
        self.tmp = Path("/tmp/test_scan_cache")
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.tmp / "cache.json"
        self.c = ScanCache(cache_path=self.cache_path, ttl_hours=24)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_initial_cache(self):
        stats = self.c.get_stats()
        assert stats["total_entries"] == 0

    def test_is_cached_fresh(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        mtime = f.stat().st_mtime
        from security_scanner.utils import file_hash, text_hash
        ch = file_hash(f) or ""
        fh = text_hash("[]")
        self.c.mark_cached(f, mtime, ch, fh)
        assert self.c.is_cached(f)

    def test_is_cached_after_modification(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        mtime = f.stat().st_mtime
        from security_scanner.utils import file_hash, text_hash
        ch = file_hash(f) or ""
        fh = text_hash("[]")
        self.c.mark_cached(f, mtime, ch, fh)
        assert self.c.is_cached(f)
        f.write_text("print('modified')")
        assert not self.c.is_cached(f)

    def test_invalidate(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x")
        from security_scanner.utils import file_hash, text_hash
        self.c.mark_cached(f, f.stat().st_mtime, file_hash(f) or "", text_hash("[]"))
        assert self.c.is_cached(f)
        self.c.invalidate(f)
        assert not self.c.is_cached(f)

    def test_clear_all(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("a")
        f2.write_text("b")
        from security_scanner.utils import file_hash, text_hash
        self.c.mark_cached(f1, f1.stat().st_mtime, file_hash(f1) or "", text_hash("[]"))
        self.c.mark_cached(f2, f2.stat().st_mtime, file_hash(f2) or "", text_hash("[]"))
        assert self.c.get_stats()["total_entries"] == 2
        self.c.clear_all()
        assert self.c.get_stats()["total_entries"] == 0

    def test_invalidate_prefix(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        f1 = tmp_path / "outside.py"
        f2 = sub / "inside.py"
        f1.write_text("a")
        f2.write_text("b")
        from security_scanner.utils import file_hash, text_hash
        self.c.mark_cached(f1, f1.stat().st_mtime, file_hash(f1) or "", text_hash("[]"))
        self.c.mark_cached(f2, f2.stat().st_mtime, file_hash(f2) or "", text_hash("[]"))
        count = self.c.invalidate_prefix(sub)
        assert count >= 1
        assert not self.c.is_cached(f2)
        assert self.c.is_cached(f1)

    def test_get_findings_hash(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x")
        from security_scanner.utils import file_hash, text_hash
        self.c.mark_cached(f, f.stat().st_mtime, file_hash(f) or "", text_hash("abc"))
        assert self.c.get_findings_hash(f) == text_hash("abc")

    def test_get_findings_hash_missing(self):
        f = Path("/nonexistent/file.py")
        assert self.c.get_findings_hash(f) is None

    def test_persistence_across_instances(self, tmp_path):
        cache_file = tmp_path / "persist.json"
        c1 = ScanCache(cache_path=cache_file)
        f = tmp_path / "test.py"
        f.write_text("x")
        from security_scanner.utils import file_hash, text_hash
        c1.mark_cached(f, f.stat().st_mtime, file_hash(f) or "", text_hash("[]"))
        c2 = ScanCache(cache_path=cache_file)
        assert c2.is_cached(f)

    def test_expired_ignored_on_load(self, tmp_path):
        cache_file = tmp_path / "expired.json"
        entry = CacheEntry(mtime=1.0, content_hash="a", findings_hash="b",
                           cached_at=time.time() - 999999)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps({
            str(tmp_path / "old.py"): entry.to_dict()
        }), encoding="utf-8")
        c = ScanCache(cache_path=cache_file, ttl_hours=1)
        assert c.get_stats()["total_entries"] == 0

    def test_stats(self):
        stats = self.c.get_stats()
        assert "total_entries" in stats
        assert "avg_age_seconds" in stats
        assert "ttl_hours" in stats
