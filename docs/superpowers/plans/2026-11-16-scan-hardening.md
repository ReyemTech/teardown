# Scan Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make passive scans safer, more accurate, bounded, and release-ready.

**Architecture:** Keep the 1.0 JSON shape and injected Fetcher boundary. Sanitize values at collection, enforce network scope and body limits in HttpClient, and validate API evidence before recording it. Bound liveness work before fan-out.

**Tech Stack:** Python 3.10+, httpx, pytest, GitHub Actions.

**Spec:** `docs/design.md` and the follow-up request in this conversation.

## Global Constraints

- Passive public frontend signals only; no authentication or exploitation.
- Secrets never stored in full.
- Offline, fast tests; no collector imports httpx.
- Preserve schema 1.0 field names and shapes.

## Review Focus

- Public suffix domains such as `example.co.uk` must enumerate the correct root.
- Redirects to an unrelated host must not be followed during scan probes.
- Headers and URLs containing credentials must not leak through JSON or errors.
- Generic HTML fallbacks must not count as API endpoints.
- A large crt.sh response must not cause unbounded liveness requests.

---

### Task 1: Output redaction

**Files:** `teardown/collectors/html_js.py`, `teardown/collectors/headers.py`, `teardown/http_client.py`, tests.

**Interfaces:** Keep existing model fields; redact credential-like values before assigning them.

- [x] Write failing tests for third-party keys, sensitive headers, and credential-bearing URLs/errors.
- [x] Run the focused tests to verify failure.
- [x] Implement collection-time redaction and re-run focused and full tests.

### Task 2: Scope and root domain

**Files:** `teardown/cli.py`, `teardown/http_client.py`, `teardown/collectors/html_js.py`, tests, `pyproject.toml`.

**Interfaces:** Resolve registrable domains using a bundled public suffix snapshot; HttpClient accepts the scan root and limits redirects and fetched assets to scope.

- [x] Write failing tests for public suffix roots and out-of-scope URLs/redirects.
- [x] Run focused tests to verify failure.
- [x] Implement scope enforcement and re-run focused and full tests.

### Task 3: API evidence

**Files:** `teardown/collectors/api_discovery.py`, tests.

**Interfaces:** Preserve `ApiSurface`; only record API signals supported by status and response shape.

- [x] Write failing tests for HTML fallbacks, arbitrary JSON, and foreign redirects.
- [x] Run focused tests to verify failure.
- [x] Implement evidence checks and re-run focused and full tests.

### Task 4: Bounded scans

**Files:** `teardown/cli.py`, `teardown/http_client.py`, tests.

**Interfaces:** Add a liveness probe cap and a streamed response byte limit.

- [x] Write failing tests for capped probes and truncated responses.
- [x] Run focused tests to verify failure.
- [x] Implement limits and re-run focused and full tests.

### Task 5: Delivery and docs

**Files:** `.github/workflows/ci.yml`, `README.md`, `PUBLISHING.md`.

- [x] Add CI for Python 3.10–3.14, offline tests, build, and installed-wheel CLI smoke test.
- [x] Document scope, limits, redaction, evidence rules, and release workflow.
- [x] Run the full suite and local package smoke test.
