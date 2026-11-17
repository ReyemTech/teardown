# Teardown Tool

Passive web-app architecture reconnaissance with subdomain fan-out. It collects
public frontend signals and writes a versioned JSON record for agents plus a
vault-compatible Markdown report for people. Collection is deterministic;
interpretation belongs to the agent reading the JSON.

**Passive recon only.** No authenticated access, no exploitation. Active DNS
brute-force is opt-in (`--active-dns`) and off by default.

## Run with uvx (no install)

```bash
# Once published to PyPI:
uvx teardown example.com --single

# Straight from the repo (works today):
uvx --from git+https://github.com/ReyemTech/teardown teardown example.com --single
```

The command and distribution are both `teardown`. `uvx` builds an
ephemeral environment and runs it — nothing to install. For the active-DNS extra:
`uvx --with dnspython --from git+https://github.com/ReyemTech/teardown teardown example.com --active-dns`.

## Local dev install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[active-dns,mcp]'
.venv/bin/teardown example.com --single
```

`dnspython` is only needed for `--active-dns`; the passive path runs without it.

## Usage

```bash
# Single host, no subdomain enumeration
teardown example.com --single --out-dir .

# Full: enumerate via crt.sh, CertSpotter and Wayback; check up to 100 hosts
teardown example.com --out-dir .

# Limit liveness checks and host teardowns separately
teardown example.com --max-probes 40 --max-hosts 10

# Add installed subfinder's passive sources
teardown example.com --subfinder

# Opt in to active DNS brute-force
teardown example.com --active-dns --wordlist words.txt

# Machine output only (no files)
teardown example.com --single --json-only

# Compare two saved JSON scans
teardown diff last-month.json this-month.json

# Fetch and convert the optional community fingerprint database
teardown fingerprints update
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--single` | off | Scan only the given host; skip enumeration. |
| `--active-dns` | off | Add DNS brute-force (needs `dnspython`). |
| `--subfinder` | off | Merge installed subfinder's passive results. |
| `--wordlist PATH` | built-in | Wordlist for `--active-dns`. |
| `--max-hosts N` | 25 | Cap live hosts torn down (0 = no cap). |
| `--max-probes N` | 100 | Cap enumerated hosts checked for liveness (0 = no cap). |
| `--concurrency N` | 10 | Max concurrent requests. |
| `--rate R` | 8.0 | Global requests/sec cap. |
| `--out-dir DIR` | `.` | Where JSON + markdown land. |
| `--name NAME` | from domain | Output basename. |
| `--json-only` | off | Print JSON to stdout, write nothing. |
| `--cache-dir DIR` | `.teardown-cache/` | Daily response cache location. |
| `--no-cache` | off | Fetch fresh responses. |

## Output

Two files per scan: `<name>-teardown.json` (machine, versioned schema) and
`<name>-teardown.md` (vault-ready, matches the existing teardown frontmatter).

The **JSON is the contract an agent reads** — one `HostTeardown` record per host
inside a `ScanResult` rollup. Shapes are defined in `teardown/models.py`
(`SCHEMA_VERSION`). An agent should consume the JSON and narrate; the markdown is
for humans.

Schema 1.2 adds `detections` per host, `aggregate.detections_union`, and
namespaced `extensions` for additional scan modules. Each detection
record has a technology name,
categories, deterministic `confidence` (0–100), and signal labels in `evidence`.
Confidence reflects matched signal strength and corroboration; it is not a
statistically calibrated probability. The legacy `frameworks` and `cms` views
remain. `http` now includes page title, redirect status chain, observed TLS
version/cipher/certificate expiry and CDN header fingerprint when available.
`teardown diff` reports added and removed hosts plus field changes; scan times
and volatile response headers are excluded.

The wheel bundles 589 MIT-licensed fingerprints (588 from OpenTechAlyzer plus
the Livewire definition). `teardown fingerprints update` downloads and converts
the larger WebAppAnalyzer database automatically into the user's local cache.
That optional dataset is GPL-3.0 and is not distributed with this repository or
wheel. Set `TEARDOWN_FINGERPRINT_DB` to choose its local path. Imported
definitions update bundled names; the local curated definitions take final
precedence. Attribution is in
[`teardown/data/LICENSE.md`](teardown/data/LICENSE.md).

## MCP server

Install the optional extra, then use stdio or local Streamable HTTP:

```bash
.venv/bin/python -m pip install -e '.[mcp]'
teardown-mcp
teardown-mcp --transport http --host 127.0.0.1 --port 8000
```

The HTTP endpoint is `http://127.0.0.1:8000/mcp`. The tools are
`teardown_host`, `teardown_domain`, `enumerate_subdomains`, `scan_domain`
(compatibility alias), and `diff_scans` (two JSON objects). They reuse the CLI
collection path. The default bind address is loopback. See
[`.mcp.json.example`](.mcp.json.example) for a stdio registration example.

## How collection behaves

- The registrable root domain comes from a bundled public suffix list, so a
  target such as `app.example.co.uk` enumerates `example.co.uk`. This does not
  fetch the suffix list during a scan. Private suffixes are respected, so
  `app.foo.github.io` stays within the `foo.github.io` tenant.
- The scan fetches only hosts under that root, plus crt.sh, CertSpotter and
  Wayback for passive enumeration. It stops at redirects outside that scope.
  Third-party asset URLs
  may appear in the result, but their bodies are not fetched.
- Liveness checks stop after `--max-probes` candidates. The 25-host teardown cap
  applies after liveness checks. The liveness response is reused for collection.
  Each HTTP response body is limited to 8 MB.
- GET responses are cached by URL and UTC day under `.teardown-cache/` so a
  rerun resumes without repeating successful requests. Bodies mentioning
  sensitive concepts, containing long opaque values, or matching recognized
  secret patterns are not persisted. The cache keeps only cookie names, never
  cookie values.
- API paths count as observed only when their responses support the claim: REST
  requires JSON or an access-denied status; GraphQL requires a GraphQL-shaped
  response; OpenAPI requires a version marker and `paths` object. A generic
  HTML fallback does not count. A source map must parse as a v3 source map.
- Extracted keys are stored as prefixes, credential-bearing headers are
  redacted, and sensitive URL query values are masked in output. Inspect the
  JSON before sharing it: public pages can contain identifiers outside these
  recognized patterns. Assets with credential-bearing query parameters are
  listed with masked URLs and may not be fetchable for bundle enrichment.

## Architecture

```
teardown/
  models.py       # versioned dataclasses — the contract
  http_client.py  # polite async httpx client + Fetcher protocol
  safety.py       # output redaction + request scope checks
  fingerprints.py # database matcher + optional WebAppAnalyzer importer
  scan_modules.py # ordered, injectable host scan modules
  cache.py        # sanitized daily response cache
  collectors/
    headers.py    # headers + CSP
    html_js.py    # CMS details, bundles, third-parties, secret leaks
    api_discovery.py  # REST / GraphQL / OpenAPI / WordPress probes
  enumerate.py    # passive source adapters + optional DNS/subfinder + liveness
  diff.py         # normalized cross-run comparison
  mcp_server.py   # optional stdio / Streamable HTTP server
  analyze.py      # signals -> OPSEC findings + cross-host aggregate
  render.py       # JSON writer + vault markdown
  cli.py          # argparse + asyncio orchestration
```

Collectors take an injected `Fetcher` so they unit-test with a fake, no network.
Design notes: [`docs/design.md`](docs/design.md).

### Adding a scan module

Built-in host scans run as named modules over the same fetched response and
injected `Fetcher`. To add a collector in Python, register it before calling
`run_scan` in the same process:

```python
from teardown.scan_modules import ScanModule, register_module

async def collect(context):
    # Use context.fetcher for any bounded, in-scope request.
    return {"public_marker": "observed"}

register_module(ScanModule("example", collect))
```

The returned mapping appears at `hosts[].extensions.example` in the JSON.
Modules run independently, so one collector's error does not stop later ones.
For a built-in addition, add the module to `scan_modules.py`; use
`run_scan(..., modules=[...])` to select modules for one scan. Keep module
payloads deterministic and redact secret values before returning them.

## Tests

```bash
.venv/bin/python -m pytest -q    # offline
```

## Notes & gotchas

- **crt.sh is flaky** — it intermittently returns a 404/HTML error page. The
  enumerator retries (with backoff) and falls back to the bare-domain query form.
- **Source-map findings are first-party only.** A third-party CDN (Sentry,
  jsdelivr) publishing maps for its own SDK is not the target's exposure, so those
  are skipped; first-party maps are flagged MEDIUM (info disclosure, not a
  credential leak).
- **Secrets are redacted at collection and output boundaries.** Third-party keys
  keep only a prefix, and sensitive headers and URL query values are masked.
- Astro is matched from `/_astro/` JS and stylesheet URLs as well as its page
  markers. Hosting labels follow current response evidence; a prior Cloudflare
  result does not carry forward when a host now identifies Fastly or GitHub Pages.
