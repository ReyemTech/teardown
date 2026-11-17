# AGENTS.md

Dev guide for `teardown` — a passive web-app architecture recon CLI with
subdomain fan-out. Read this before changing code.

## What this is

Reverse-engineers a web app's architecture from **publicly accessible frontend
signals only** — no auth, no exploitation. Given a domain it:

1. Enumerates subdomains (crt.sh, CertSpotter, Wayback passive; optional
   subfinder; `--active-dns` opt-in DNS brute).
2. Filters to live hosts.
3. Tears down each host: headers, CSP, framework/CMS, JS bundles + source maps,
   REST/GraphQL/OpenAPI/WordPress API surface, third-party fingerprints, redacted
   secret leaks, OPSEC findings.
4. Emits an **agent-readable JSON contract** (`ScanResult`/`HostTeardown`, schema
   1.6) plus a vault-compatible markdown rendering and cross-run diff.

The guiding split: **deterministic collection (this code) vs. interpretation (the
agent that reads the JSON).** Keep narrative/judgment out of the tool; it produces
normalized signals and the mechanical findings, nothing fuzzier.

## Layout

```
teardown/
  models.py          # THE contract — dataclasses + SCHEMA_VERSION. Change carefully.
  http_client.py     # async httpx client + Fetcher protocol + FetchResponse
  fingerprints.py   # data-driven matcher + optional upstream importer
  scan_modules.py   # ordered, injectable host collectors
  data/             # bundled MIT fingerprints and attribution
  cache.py          # sanitized daily response cache
  history.py        # private SQLite history + per-host checkpoints
  terminal.py       # CLI progress and styled history/compare output
  network.py        # bounded DNS + RIPEstat route/registration attribution
  hosting.py        # provider-owned CNAME attribution rules
  artifacts.py      # private sanitized JS and source-map retention
  sourcemap_intel.py # pure source-map inventory and embedded OpenAPI parser
  collectors/
    headers.py       # parse_headers, parse_csp               (pure)
    html_js.py       # frameworks/CMS, bundles, third-parties, secret leaks; enrich_bundles (fetcher)
    api_discovery.py # discover_api                            (fetcher)
  enumerate.py       # enumerate_subdomains, filter_live       (fetcher)
  diff.py            # stable cross-run comparison
  mcp_server.py      # optional FastMCP stdio / Streamable HTTP
  analyze.py         # analyze_host, build_aggregate           (pure)
  render.py          # render_markdown, render_host_markdown, write_outputs  (pure)
  cli.py / __main__  # argparse + asyncio orchestration
tests/               # pytest, fully offline (fake Fetcher)
docs/design.md       # the design doc / why
```

## Core conventions (do not break)

- **Collectors never import httpx.** Anything that needs the network takes an
  injected `Fetcher` (see `http_client.Fetcher`); pure parsers take already-fetched
  text/headers and return partial model objects. This is what keeps tests offline.
- **`Fetcher.get/request` never raise.** Failures come back as `FetchResponse` with
  `status=None` / `error` set. Collector code must tolerate that, not try/except the
  network.
- **Secrets are never stored in full** — only a redacted prefix (`value_prefix`).
  Tests assert the full secret is absent from output. Keep it that way.
- **Passive only.** No authenticated requests, no exploit payloads, no evasion.
  `--active-dns` is the only active enumeration path and is opt-in. Passive
  source adapters must stay bounded and scope-filtered.
- **Politeness lives in `HttpClient`** (bounded semaphore + token-bucket rate limit +
  identifying UA). Don't bypass it with raw httpx calls.
- **Machine JSON stays on stdout.** Progress and scan summaries go to stderr;
  `--json-only` skips report files but still saves SQLite history unless disabled.
- **Local data defaults to `~/.teardown`.** Honor `--data-dir`/`TEARDOWN_HOME`,
  keep private file permissions, and never persist unredacted credentials.
- **Source-map artifacts are bounded and first-party only.** Keep the 4 MB cap,
  sanitize before writing, and honor CLI/MCP `--no-artifacts`.
- **Referenced API paths are not live endpoints.** Inventory source-map paths
  passively. Do not probe all paths or execute mutating methods based on an
  embedded spec; do not infer missing authorization from absent declarations.
- **Network attribution is observed infrastructure.** DNS A/AAAA addresses can
  be CDN edges and can differ from the HTTP connection peer. Never call them
  origin IPs or infer app operators from ASN/registry names.
- **Geo-IP is approximate.** Treat GeoLite country, city and coordinates as
  sourced estimates for the observed IP, not physical server locations. Keep
  the MaxMind attribution in reports and docs; suppress unknown placeholders.
- `from __future__ import annotations` at the top of every module; `requires-python
  >= 3.10`.

## Running

```bash
# tests (must stay offline + fast, ~0.1s)
python -m venv .venv && .venv/bin/pip install -e '.[active-dns]' pytest pytest-asyncio
.venv/bin/python -m pytest -q

# run the CLI in dev
.venv/bin/teardown example.com --single --json-only

# run exactly as users do, from the git remote
uvx --from git+ssh://git@github.com/ReyemTech/teardown teardown example.com --single
```

Publishing to PyPI: see `PUBLISHING.md`. Merging a Conventional Commit to
`main` automatically versions, tags, and publishes `tech-teardown`.

## Extending

- **New third-party / secret fingerprint:** add the regex to `html_js.py`
  (`fingerprint_third_parties` / `detect_secret_leaks`) with a redaction, and a
  fixture test in `tests/test_html_js.py`. Mirror the pattern style already there.
- **New technology fingerprint:** add data to `teardown/data/curated.json`, or
  update the MIT upstream conversion with `scripts/update_builtin_fingerprints.mjs`.
  Match on existing passive signals and keep evidence free of raw secret values.
- **New OPSEC finding:** add the rule in `analyze.py::analyze_host`, pick the right
  `Severity`, cite the actual value in `detail`, set `evidence_url` when derivable,
  and add a test that it fires on the signal AND does NOT fire on a clean host.
- **New collector:** implement a `ScanModule` over `ScanContext`, use its injected
  `Fetcher`, and add it to `scan_modules.py` or register it in-process. Return a
  redacted mapping for the namespaced `HostTeardown.extensions` payload and
  give it an offline fake-Fetcher test.
- **Schema change:** edit `models.py`, bump `SCHEMA_VERSION`, and update
  `render.py` + any consumer. The JSON is a contract other agents read — treat a
  field rename as breaking.

## Known gotchas (already handled — don't regress)

- **crt.sh is flaky** — intermittently returns a 404/HTML error page (a "successful"
  HTTP response the client won't retry). `enumerate.py` retries at the app layer with
  backoff and a bare-domain query fallback. `CRTSH_RETRY_BACKOFF` is a module constant
  so tests can zero it.
- **Source-map findings are first-party only, severity MEDIUM.** A third-party CDN
  (Sentry, jsdelivr) publishing a map for its own SDK is not the target's exposure.
  Don't re-classify these as CRITICAL or drop the first-party check.
- Server-rendered stacks can now be detected from headers, cookies and markup.
  Preserve cookie names for matching, but never cookie values.

## Commits

Conventional, imperative subject. **No AI/Claude co-authorship trailers.**
