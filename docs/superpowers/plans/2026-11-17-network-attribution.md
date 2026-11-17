# Network Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add evidence-backed DNS, ASN, routed-prefix and network-holder records to each scanned host.

**Architecture:** A named scan module receives a bounded DNS resolver and the existing Fetcher. It uses the same HttpClient for three allowlisted RIPEstat endpoints, and stores structured results on HostTeardown. Existing JSON/history/diff serialization carries the additive contract.

**Tech Stack:** Python 3.10+, dnspython, httpx via Fetcher, pytest.

**Spec:** `docs/superpowers/specs/2026-11-17-network-attribution-design.md`

## Global Constraints

- Passive, bounded collection only; no origin inference, geolocation or expanded host probing.
- Eight IP addresses and eight CNAME hops maximum per host.
- Network errors become empty fields or normalized errors; scans continue.
- No raw HTTP requests in collectors. All HTTP passes through HttpClient.
- Keep JSON redacted and deterministic; schema version becomes 1.3.

## Review Focus

- Multiple A/AAAA answers: retain both families and cap the combined count.
- CNAME loops: stop within eight hops and record truncation.
- Private/reserved IPs: do not send them to RIPEstat.
- Multiple origin ASNs: retain all, not just the first.
- CDN edge: label the address correctly and avoid claiming an origin.

---

### Task 1: Resolver and contract

**Files:** `teardown/models.py`, `teardown/network.py`, `teardown/http_client.py`, `pyproject.toml`, `tests/test_network.py`.

**Interfaces:** `resolve_dns(host: str) -> DnsObservation` on HttpClient, with injectable resolver in tests; `HostTeardown.network: NetworkInfo`.

- [ ] Write offline tests for A/AAAA/CNAME normalization, loops, cap, and private addresses.
- [ ] Run the tests and confirm they fail.
- [ ] Implement typed model and bounded DNS resolution, routed through HttpClient's rate limiter.
- [ ] Run the focused tests and commit.

### Task 2: Network enrichment module

**Files:** `teardown/network.py`, `teardown/scan_modules.py`, `teardown/cli.py`, `teardown/http_client.py`, `tests/test_network.py`.

**Interfaces:** `collect_network(host, fetcher) -> NetworkInfo`; `Fetcher.get` for allowlisted RIPEstat paths.

- [ ] Write offline tests for prefix/ASNs, holder variants, missing results, and CDN labels.
- [ ] Run the tests and confirm they fail.
- [ ] Add allowlisted RIPEstat calls and named network module; inject DNS result through the Fetcher.
- [ ] Run focused and full tests; commit.

### Task 3: Output and release

**Files:** `teardown/render.py`, `teardown/terminal.py`, `README.md`, `AGENTS.md`, `tests/test_render.py`, `tests/test_network.py`.

**Interfaces:** Existing `to_dict`, Markdown renderer, history/diff.

- [ ] Write tests for network JSON, Markdown, and historical change reporting.
- [ ] Run tests and confirm they fail.
- [ ] Render source-qualified network details; update documentation and CLI summary.
- [ ] Run all offline tests, `uv build --no-sources`, wheel smoke, and `git diff --check`.
- [ ] Commit, push, merge after CI, and verify PyPI publication.
