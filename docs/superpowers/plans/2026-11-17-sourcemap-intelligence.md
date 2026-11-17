# Source-map Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn exposed first-party source maps into bounded, agent-readable intelligence with a full Markdown inventory.

**Architecture:** A pure source-map analyzer extracts source inventory, route references, and embedded OpenAPI structure from an already fetched map. The bundle collector attaches the result; rendering summarizes it.

**Tech Stack:** Python 3.10+, dataclasses, JSON, pytest.

**Spec:** `docs/superpowers/specs/2026-11-17-sourcemap-intelligence-design.md`

## Review Focus

- A dependency source is not labeled first-party application source.
- Maps without `sourcesContent` are not described as recovered source code.
- API paths are referenced only; no reachability or authorization claim.
- Secrets and raw source text do not enter JSON or Markdown.
- Malformed/oversized maps do not break a host scan.

## Task 1: Pure analyzer

Files: `teardown/sourcemap_intel.py`, `teardown/models.py`, `tests/test_sourcemap_intel.py`.

- Write failing tests for source classification, content coverage, embedded OpenAPI, bounded inventories, malformed maps and no-content maps.
- Implement typed schema 1.6 and pure analyzer with explicit size/count caps.
- Run focused tests.

## Task 2: Scan and report integration

Files: `teardown/collectors/html_js.py`, `teardown/render.py`, `tests/test_artifacts.py`, `tests/test_render.py`.

- Write failing tests proving only first-party maps receive intel and report presents full bounded source/API-path appendix with grounded OWASP references.
- Wire analyzer after map validation and use its fields in Markdown. Keep existing OPSEC severity.
- Run focused and full tests.

## Task 3: Documentation and release

Files: `README.md`, `AGENTS.md`, `docs/design.md`.

- Explain scope and caveats.
- Run full tests, build, wheel smoke, independent review, and diff check.
- Commit, open PR, merge after CI, verify release.
