# Teardown Tool

Passive web-app architecture reconnaissance with subdomain fan-out. The code
version of the `teardown` agent: deterministic collection + an agent-readable
JSON contract, plus a vault-compatible markdown rendering.

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

# Full: enumerate subdomains (crt.sh) + tear down each live host (cap 25)
teardown example.com --out-dir .

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

## Architecture

```
teardown/
  models.py       # versioned dataclasses — the contract
  http_client.py  # polite async httpx client + Fetcher protocol
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
.venv/bin/python -m pytest -q    # 88 tests, offline
```

## Notes & gotchas

- **crt.sh is flaky** — it intermittently returns a 404/HTML error page. The
  enumerator retries (with backoff) and falls back to the bare-domain query form.
- **Source-map findings are first-party only.** A third-party CDN (Sentry,
  jsdelivr) publishing maps for its own SDK is not the target's exposure, so those
  are skipped; first-party maps are flagged MEDIUM (info disclosure, not a
  credential leak).
- **Secrets are never stored in full** — only a redacted prefix.
