"""Data-driven attribution of known provider-owned CNAME targets."""

from __future__ import annotations

import json
import re
from importlib.resources import files

from .models import HostingEvidence


def detect_cname_providers(chain: list[str]) -> list[HostingEvidence]:
    rules = json.loads(files("teardown").joinpath("data/cname_providers.json").read_text())
    found: list[HostingEvidence] = []
    seen: set[tuple[str, str]] = set()
    for raw_host in chain:
        host = raw_host.rstrip(".").lower()
        for rule in rules:
            suffix = rule.get("suffix")
            matches = (host == suffix or host.endswith("." + suffix)) if suffix else bool(
                re.search(rule["regex"], host, re.IGNORECASE))
            key = (rule["name"], rule["role"])
            if matches and key not in seen:
                seen.add(key)
                found.append(HostingEvidence(name=rule["name"], role=rule["role"],
                                             confidence=rule["confidence"], evidence=raw_host))
    return found
