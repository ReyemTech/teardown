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
uvx reyem-teardown example.com --single

# Straight from the repo (works today):
uvx --from git+https://github.com/ReyemTech/teardown teardown example.com --single
```

The command is `teardown`; the distribution is `reyem-teardown`. `uvx` builds an
ephemeral environment and runs it — nothing to install. For the active-DNS extra:
`uvx --with dnspython --from git+https://github.com/ReyemTech/teardown teardown example.com --active-dns`.

## Local dev install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[active-dns]'
.venv/bin/teardown example.com --single
```

`dnspython` is only needed for `--active-dns`; the passive path runs without it.

## Usage

```bash
# Single host, no subdomain enumeration
teardown example.com --single --out-dir .

# Full: enumerate subdomains (crt.sh), check up to 100, tear down up to 25 live hosts
teardown example.com --out-dir .

# Limit liveness checks and host teardowns separately
teardown example.com --max-probes 40 --max-hosts 10

# Opt in to active DNS brute-force on top of crt.sh
teardown example.com --active-dns --wordlist words.txt

# Machine output only (no files)
teardown example.com --single --json-only
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--single` | off | Scan only the given host; skip enumeration. |
| `--active-dns` | off | Add DNS brute-force (needs `dnspython`). |
| `--wordlist PATH` | built-in | Wordlist for `--active-dns`. |
| `--max-hosts N` | 25 | Cap live hosts torn down (0 = no cap). |
| `--max-probes N` | 100 | Cap enumerated hosts checked for liveness (0 = no cap). |
| `--concurrency N` | 10 | Max concurrent requests. |
| `--rate R` | 8.0 | Global requests/sec cap. |
| `--out-dir DIR` | `.` | Where JSON + markdown land. |
| `--name NAME` | from domain | Output basename. |
| `--json-only` | off | Print JSON to stdout, write nothing. |

## Output

Two files per scan: `<name>-teardown.json` (machine, versioned schema) and
`<name>-teardown.md` (vault-ready, matches the existing teardown frontmatter).

The **JSON is the contract an agent reads** — one `HostTeardown` record per host
inside a `ScanResult` rollup. Shapes are defined in `teardown/models.py`
(`SCHEMA_VERSION`). An agent should consume the JSON and narrate; the markdown is
for humans.

## How collection behaves

- The registrable root domain comes from a bundled public suffix list, so a
  target such as `app.example.co.uk` enumerates `example.co.uk`. This does not
  fetch the suffix list during a scan. Private suffixes are respected, so
  `app.foo.github.io` stays within the `foo.github.io` tenant.
- The scan fetches only hosts under that root, plus `crt.sh` for passive
  enumeration. It stops at redirects outside that scope. Third-party asset URLs
  may appear in the result, but their bodies are not fetched.
- Liveness checks stop after `--max-probes` candidates. The 25-host teardown cap
  applies after liveness checks. Each HTTP response body is limited to 8 MB.
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
  collectors/
    headers.py    # headers + CSP
    html_js.py    # frameworks/CMS, bundles, third-parties, secret leaks
    api_discovery.py  # REST / GraphQL / OpenAPI / WordPress probes
  enumerate.py    # crt.sh (passive) + optional DNS brute + liveness
  analyze.py      # signals -> OPSEC findings + cross-host aggregate
  render.py       # JSON writer + vault markdown
  cli.py          # argparse + asyncio orchestration
```

Collectors take an injected `Fetcher` so they unit-test with a fake, no network.
Design notes: [`docs/design.md`](docs/design.md).

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
