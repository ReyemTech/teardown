# Modular host scans and Astro evidence

The live `stint.reyem.tech` homepage currently links to `/_astro/*.js` and
`/_astro/*.css`, while the bundled Astro rule only matches islands, a generator
tag, and other inline markers. The new detector therefore misses a deployment
the older substring matcher identified. Its current HTTP response has GitHub
Pages and Fastly evidence, with no Cloudflare response evidence. We will add
asset URL rules for Astro and a direct Fastly header check; we will not infer
Cloudflare from the old report.

Host collection will execute an ordered set of named `ScanModule`s. Built-in
modules own HTTP/CSP, technology detection, bundles, third parties, secrets,
and API surface. Each takes a `ScanContext` containing the already fetched
response and injected `Fetcher`. A module failure records its name and error
type, then subsequent modules still run. Mechanical OPSEC analysis runs after
all collection modules so it sees their combined signals.

An additional module can be passed to `teardown_host` / `run_scan` or registered
in code. It returns a JSON-compatible mapping stored under its name in
`HostTeardown.extensions`. The extension boundary redacts sensitive keys and
URLs. Schema 1.2 adds only the `extensions` field; all existing host fields
retain their meaning. The diff includes extensions automatically.

Offline tests will reproduce the observed Astro/Fastly signals, verify the
module order and failure isolation, and prove an injected module lands in the
JSON payload without extra network calls.
