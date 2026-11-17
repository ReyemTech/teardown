"""Deterministic comparison of the stable parts of two ScanResult JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_VOLATILE_HEADERS = {"date", "age", "expires", "last-modified", "etag", "set-cookie",
                     "cf-ray", "x-request-id", "x-amz-cf-id", "report-to", "nel"}
_EXCLUDED = {"scanned_at", "errors", "local_path"}


def _normalized(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalized(item) for key, item in sorted(value.items())
                if key not in _EXCLUDED and (key not in _VOLATILE_HEADERS)}
    if isinstance(value, list):
        items = [_normalized(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _changes(old: Any, new: Any, prefix: str = "") -> list[dict]:
    if old == new:
        return []
    if isinstance(old, dict) and isinstance(new, dict):
        result: list[dict] = []
        for key in sorted(old.keys() | new.keys()):
            result.extend(_changes(old.get(key), new.get(key), f"{prefix}.{key}" if prefix else key))
        return result
    return [{"path": prefix, "before": old, "after": new}]


def diff_results(old: dict, new: dict) -> dict:
    if old.get("root_domain") != new.get("root_domain"):
        raise ValueError("scan root domains differ")
    old_hosts = {host["host"]: _normalized(host) for host in old.get("hosts", [])}
    new_hosts = {host["host"]: _normalized(host) for host in new.get("hosts", [])}
    changed = [{"host": host, "changes": changes}
               for host in sorted(old_hosts.keys() & new_hosts.keys())
               if (changes := _changes(old_hosts[host], new_hosts[host]))]
    return {
        "root_domain": old["root_domain"],
        "old_schema_version": old.get("schema_version"),
        "new_schema_version": new.get("schema_version"),
        "added_hosts": sorted(new_hosts.keys() - old_hosts.keys()),
        "removed_hosts": sorted(old_hosts.keys() - new_hosts.keys()),
        "changed_hosts": changed,
    }


def diff_files(old_path: str, new_path: str) -> dict:
    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    return diff_results(old, new)
