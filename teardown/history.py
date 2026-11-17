"""Private SQLite history of normalized scans and per-host checkpoints."""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from .diff import diff_results
from .models import HostTeardown, ScanResult, to_dict


def data_home(override: str | Path | None = None) -> Path:
    """Resolve the local data directory; callers may override it explicitly."""
    value = override if override is not None else os.environ.get("TEARDOWN_HOME")
    return Path(value).expanduser() if value else Path.home() / ".teardown"


def ensure_data_home(override: str | Path | None = None) -> Path:
    directory = data_home(override)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    return directory


class HistoryStore:
    def __init__(self, home: str | Path | None = None) -> None:
        directory = ensure_data_home(home)
        self.path = directory / "history.sqlite3"
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        if os.name != "nt":
            self.path.chmod(0o600)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                root_domain TEXT NOT NULL,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                schema_version TEXT,
                result_json TEXT
            );
            CREATE INDEX IF NOT EXISTS scans_domain_time
                ON scans(root_domain, started_at DESC);
            CREATE TABLE IF NOT EXISTS host_results (
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, host)
            );
        """)
        self.connection.commit()

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def start(self, root_domain: str, target: str, started_at: str) -> str:
        scan_id = uuid.uuid4().hex
        self.connection.execute(
            "INSERT INTO scans(id, root_domain, target, started_at, status) "
            "VALUES (?, ?, ?, ?, 'running')",
            (scan_id, root_domain, target, started_at),
        )
        self.connection.commit()
        return scan_id

    def checkpoint(self, scan_id: str, host: HostTeardown) -> None:
        payload = json.dumps(to_dict(host), sort_keys=True)
        self.connection.execute(
            "INSERT OR REPLACE INTO host_results "
            "(scan_id, host, completed_at, payload_json) VALUES (?, ?, ?, ?)",
            (scan_id, host.host, host.scanned_at, payload),
        )
        self.connection.commit()

    def finish(self, scan_id: str, result: ScanResult) -> None:
        for host in result.hosts:
            self.checkpoint(scan_id, host)
        payload = json.dumps(to_dict(result), sort_keys=True)
        self.connection.execute(
            "UPDATE scans SET status='complete', finished_at=?, "
            "schema_version=?, result_json=? WHERE id=?",
            (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             result.schema_version, payload, scan_id),
        )
        self.connection.commit()

    def fail(self, scan_id: str) -> None:
        self.connection.execute(
            "UPDATE scans SET status='incomplete', finished_at=? WHERE id=?",
            (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), scan_id),
        )
        self.connection.commit()

    def list_scans(self, root_domain: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute("""
            SELECT s.id, s.root_domain, s.target, s.started_at, s.finished_at,
                   s.status, s.schema_version,
                   (SELECT COUNT(*) FROM host_results h WHERE h.scan_id=s.id) AS host_count
            FROM scans s WHERE s.root_domain=?
            ORDER BY s.started_at DESC, s.rowid DESC LIMIT ?
        """, (root_domain, limit)).fetchall()
        return [dict(row) for row in rows]

    def latest_result(self, root_domain: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT result_json FROM scans WHERE root_domain=? AND status='complete' "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1", (root_domain,),
        ).fetchone()
        if row is None:
            raise ValueError(f"no completed scan for {root_domain}")
        return json.loads(row["result_json"])

    def compare(self, root_domain: str, days: int | None = None) -> dict[str, Any]:
        latest = self.connection.execute(
            "SELECT id, started_at, result_json FROM scans "
            "WHERE root_domain=? AND status='complete' "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1", (root_domain,),
        ).fetchone()
        if latest is None:
            raise ValueError(f"no completed scan for {root_domain}")
        if days is None:
            earlier = self.connection.execute(
                "SELECT id, started_at, result_json FROM scans "
                "WHERE root_domain=? AND status='complete' AND id<>? "
                "ORDER BY started_at DESC, rowid DESC LIMIT 1",
                (root_domain, latest["id"]),
            ).fetchone()
        else:
            cutoff = (dt.datetime.fromisoformat(latest["started_at"].replace("Z", "+00:00"))
                      - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            earlier = self.connection.execute(
                "SELECT id, started_at, result_json FROM scans "
                "WHERE root_domain=? AND status='complete' AND started_at<=? "
                "ORDER BY started_at DESC, rowid DESC LIMIT 1",
                (root_domain, cutoff),
            ).fetchone()
        if earlier is None:
            raise ValueError(f"no earlier completed scan for {root_domain}")
        return {
            "root_domain": root_domain,
            "old_scan_id": earlier["id"], "old_scanned_at": earlier["started_at"],
            "new_scan_id": latest["id"], "new_scanned_at": latest["started_at"],
            "diff": diff_results(json.loads(earlier["result_json"]),
                                 json.loads(latest["result_json"])),
        }
