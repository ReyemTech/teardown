"""Local scan history and checkpoint behavior; no network."""

from __future__ import annotations

import json
import os
import stat

import pytest

from teardown.history import HistoryStore, data_home
from teardown.models import HostTeardown, ScanResult


def _scan(at: str, framework: str) -> ScanResult:
    return ScanResult(root_domain="example.com", scanned_at=at, hosts=[
        HostTeardown(target="https://example.com", host="example.com",
                     scanned_at=at, reachable=True, frameworks=[framework])])


def test_data_home_uses_override_and_private_database(tmp_path, monkeypatch):
    monkeypatch.setenv("TEARDOWN_HOME", str(tmp_path / "private"))
    assert data_home() == tmp_path / "private"
    with HistoryStore() as history:
        assert history.path == tmp_path / "private" / "history.sqlite3"
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "private").stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "private" / "history.sqlite3").stat().st_mode) == 0o600


def test_history_checkpoints_and_compares_completed_scans(tmp_path):
    with HistoryStore(tmp_path) as history:
        old = _scan("2026-11-01T12:00:00Z", "react")
        old_id = history.start("example.com", "example.com", old.scanned_at)
        history.checkpoint(old_id, old.hosts[0])
        assert history.list_scans("example.com")[0]["host_count"] == 1
        assert history.list_scans("example.com")[0]["status"] == "running"
        history.finish(old_id, old)

        interrupted = history.start("example.com", "example.com", "2026-11-05T12:00:00Z")
        history.checkpoint(interrupted, old.hosts[0])
        history.fail(interrupted)

        new = _scan("2026-11-17T12:00:00Z", "astro")
        new_id = history.start("example.com", "example.com", new.scanned_at)
        history.finish(new_id, new)
        latest = history.latest_result("example.com")
        assert latest["hosts"][0]["frameworks"] == ["astro"]
        comparison = history.compare("example.com", days=7)
        assert comparison["old_scan_id"] == old_id
        assert comparison["new_scan_id"] == new_id
        assert comparison["diff"]["changed_hosts"][0]["host"] == "example.com"
        assert history.compare("example.com")["old_scan_id"] == old_id


def test_history_no_baseline_is_clear_error(tmp_path):
    with HistoryStore(tmp_path) as history:
        scan = _scan("2026-11-17T12:00:00Z", "astro")
        history.finish(history.start("example.com", "example.com", scan.scanned_at), scan)
        with pytest.raises(ValueError, match="earlier completed scan"):
            history.compare("example.com")


def test_history_stores_redacted_result(tmp_path):
    scan = ScanResult(root_domain="example.com", scanned_at="2026-11-17T12:00:00Z",
                      hosts=[HostTeardown(target="https://example.com/?token=hidden",
                                          host="example.com")])
    with HistoryStore(tmp_path) as history:
        history.finish(history.start("example.com", "example.com", scan.scanned_at), scan)
    assert "hidden" not in (tmp_path / "history.sqlite3").read_bytes().decode(errors="ignore")
