# Teardown Tool — Design

**Date:** 2026-11-16
**Status:** Approved (user opted into direct execution)
**Owner:** Mario Meyer / Reyem Tech

## Intent & Why

Today `teardown` is a Claude *agent* (`.claude/agents/teardown.md`) that improvises
`curl` commands to reverse-engineer a single web app's architecture and writes a
prose markdown teardown to the vault. It's been run ~12 times for lead intelligence
(Liteline), competitive research (HivePipe), and OPSEC self-audits.

We want a **standalone tool** that:

1. Runs the teardown logic as deterministic code, not improvised shell.
2. **Enumerates a domain's subdomains** and tears down each live host.
3. Emits results **structured for an agent to consume** — machine JSON first, with a
   vault-markdown rendering for human reading.

The split that shapes everything: **deterministic collector (code) vs. interpreter
(agent).** The tool gathers and normalizes signals and computes the mechanical OPSEC
findings; richer narrative judgment is left to whatever agent reads the JSON.

## Goals

- Single-host teardown parity with the existing agent: headers, CSP, framework/CMS
  detection, JS bundle + sourcemap scan, API discovery (REST/GraphQL/OpenAPI/WP),
  third-party fingerprinting, secret/key leak detection, OPSEC findings.
- Subdomain enumeration (passive by default), liveness filtering, fan-out teardown.
- Agent-readable structured output (versioned JSON schema), plus a vault-markdown
  renderer matching the existing teardown frontmatter/format.
- Concurrent but polite (bounded concurrency, rate limiting, identifying UA).
- Minimal deps, runnable as `python -m teardown <domain>`.

## Non-Goals

- No authenticated access, no exploitation, no credential stuffing — **passive recon
  only**, same posture as the current agent.
- No active DNS brute-force *by default* (opt-in `--active-dns` flag only).
- No persistent service/daemon; it's a CLI invoked per target.
- Not replacing the agent's narrative — the tool feeds it.

## Anti-Goals

- Anything that would make this read as a mass-scanning/attack tool: no aggressive
  rates, no exploit payloads, no evasion.

## Approaches Considered

1. **Rust CLI.** Max throughput for large fan-out, single binary. Rejected: overkill
   for this scale, slower to build/iterate, off-stack (vault tooling is all Python).
2. **Port the agent prompt to a bigger prompt.** Rejected: non-deterministic, the
   whole point is to make collection reproducible code.
3. **Python CLI, collector/interpreter split (CHOSEN).** Deterministic collectors as
   pure-ish functions over fetched responses, async orchestration via httpx, JSON +
   markdown output. On-stack, testable, fast to build.

## Architecture

```
teardown/
  models.py          # Versioned dataclasses — THE CONTRACT (schema_version 1.6)
  http_client.py     # Async httpx client: rate-limited, bounded, polite UA, retries.
                     #   Exposes a Fetcher protocol injected into collectors.
  collectors/
    headers.py       # HTTP headers -> server/powered-by/security/cache; CSP parse
    html_js.py       # HTML -> framework/CMS detect, bundle list, sourcemap check,
                     #   third-party fingerprints, secret/key leak detection
    api_discovery.py # REST/GraphQL(introspection)/OpenAPI/WP (user-enum) probes
  enumerate.py       # Subdomain enum: crt.sh (passive) + optional DNS brute; liveness
  analyze.py         # Signals -> opsec_findings[] + cross-host aggregate
  render.py          # JSON writer + vault-markdown renderer (matches existing format)
  cli.py / __main__  # argparse + asyncio orchestration + concurrency
tests/               # pytest: CSP parser, fingerprints, WP user-enum, CSP->domains,
                     #   graphql introspection parse, markdown render — fixture-driven
```

### Data contract (agent-readable)

- `HostTeardown` — one record per host. Fields: target, host, scanned_at, reachable,
  `http{status,final_url,server,powered_by,security_headers,cache,all_headers}`,
  `csp{present,directives,third_party_domains}`, `frameworks[]`,
  `cms{type,version,plugins,themes}`, `bundles[{url,type,has_sourcemap,interesting_tokens}]`,
  `api_surface{rest[],graphql{present,introspection_open,types},openapi{present,url,endpoints},wordpress{wp_json,users_enumerable,users}}`,
  `third_parties[{name,category,key,evidence}]`,
  `secret_leaks[{type,value_prefix,source_url}]`,
  `opsec_findings[{severity,title,detail,evidence_url}]`, `errors[]`.
- `ScanResult` — root_domain, scanned_at, `enumeration{sources,subdomains_found,live_hosts}`,
  `hosts[HostTeardown]`, `aggregate{tech_stack_union,third_parties_union,critical_findings}`.
- Severity enum: `critical | medium | low | info`.

### Collector decoupling

Collectors that need the network take an injected async `Fetcher` (from
`http_client`) so they're unit-testable with a fake fetcher. Pure parsers
(CSP, fingerprints) take already-fetched text/headers and return partial dicts.

### Concurrency & politeness

`asyncio` + `httpx.AsyncClient`; a global semaphore bounds concurrent hosts
(default 10), per-host probes run sequentially. Global token-bucket rate limit.
Timeouts + bounded retries. UA identifies the tool. `--active-dns` gated off by
default; passive crt.sh only unless opted in.

### Output

`<root-or-host>-teardown.json` (machine) + `<root-or-host>-teardown.md` (vault).
Multi-host: per-host JSON records inside one `ScanResult` JSON + a rollup markdown.
Output dir is a CLI arg (defaults to cwd); vault paths passed explicitly by the
caller/agent/skill.

## Left to the builder

- Exact fingerprint/regex tables (seed from the existing agent's grep patterns).
- crt.sh response shape handling + dedupe/wildcard stripping.
- Markdown frontmatter fields: mirror `references/intelligence/liteline-teardown.md`.
- Test fixtures (captured sample responses).
