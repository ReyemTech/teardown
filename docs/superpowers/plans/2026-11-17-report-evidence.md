# Report Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn DNS and first-party source maps into inspectable evidence and deterministic report summaries.

**Architecture:** Data-driven CNAME rules enrich the existing network module. A private content-addressed artifact store receives already-fetched bundle/map bodies from the bundle module. Rendering computes TL;DR and To Do sections from ScanResult without external AI.

**Tech Stack:** Python 3.10+, existing Fetcher/httpx, JSON, pathlib, pytest.

**Spec:** `docs/superpowers/specs/2026-11-17-report-evidence-design.md`

## Global Constraints

- Only first-party exposed source maps are retained; 4 MB per artifact.
- Persist sanitized content only, in 0700 directories and 0600 files.
- Existing CLI and MCP scan behavior remains passive and bounded.
- Schema version is 1.5; artifact local paths are excluded from diff normalization.
- Summaries and tasks use deterministic rules and actual evidence.

## Review Focus

- ELB must not be reported as Elastic Beanstalk without distinct evidence.
- An onrender.com CNAME before Cloudflare must retain both platform and edge observations.
- Third-party source maps must not be saved or flagged as host exposure.
- Generated JS and embedded source content must not persist known secret strings.
- No duplicate report tasks for the same finding across multiple hosts.

---

### Task 1: CNAME provider evidence

**Files:** `teardown/data/cname_providers.json`, `teardown/hosting.py`, `teardown/models.py`, `teardown/network.py`, `teardown/analyze.py`, `tests/test_hosting.py`.

- [ ] Write failing tests using Codalio-style Porter/ELB and Render/Cloudflare chains.
- [ ] Implement typed evidence, data rules, and aggregate hosting integration.
- [ ] Run focused and full offline tests.

### Task 2: Retained source-map artifacts

**Files:** `teardown/artifacts.py`, `teardown/models.py`, `teardown/collectors/html_js.py`, `teardown/scan_modules.py`, `teardown/cli.py`, `teardown/mcp_server.py`, `teardown/diff.py`, `tests/test_artifacts.py`.

- [ ] Write failing offline tests for first-party gating, sanitization, permissions, size cap and stable hashes.
- [ ] Implement the private artifact store and pass it through CLI/MCP to the bundle module.
- [ ] Run focused and full offline tests.

### Task 3: Report and release

**Files:** `teardown/render.py`, `README.md`, `AGENTS.md`, `tests/test_render.py`.

- [ ] Write failing tests for TL;DR, hosting evidence, artifact links, To Do grouping and actionable-only rules.
- [ ] Implement deterministic rendering and documentation.
- [ ] Run full tests, package build, wheel smoke and diff check.
- [ ] Commit, open PR, merge after CI, verify PyPI publication.
