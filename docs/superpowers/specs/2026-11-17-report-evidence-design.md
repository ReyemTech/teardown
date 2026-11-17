# Report evidence and actionable summary design

## Intent

Expose hosting clues already present in DNS, retain first-party source-map
evidence for local inspection, and make the report useful at a glance without
introducing AI interpretation.

## Evidence rules

- Classify CNAME targets from a small, reviewable data file. Each observation
  carries provider, role, matched hostname, and confidence. In Codalio's case,
  `onporter.run` means Porter, `*.elb.<region>.amazonaws.com` means AWS Elastic
  Load Balancing, and `onrender.com` means Render. ELB alone does not establish
  Elastic Beanstalk. Cloudflare CNAMEs describe CDN edges, not origin hosting.
- Aggregate hosting/platform observations from per-host evidence, preserving
  roles. A provider name must not be inferred from an ASN alone when the CNAME
  gives a more specific platform name.
- Save the generated JS and valid source map for first-party exposed maps only,
  using the responses already fetched. Store bounded, sanitized, content-hashed
  local copies under `~/.teardown/artifacts` with private permissions. Keep the
  source map's structure and embedded `sourcesContent` for inspection, with
  recognizable secret values redacted. Never persist raw credential strings.
  If a body exceeds the 4 MB artifact cap or cannot be sanitized safely, skip
  saving it and keep the public evidence URL. Add stable hashes and local paths
  to the bundle record; ignore local paths in cross-run diffs.
- Artifacts are saved by default for first-party exposed maps. CLI
  `--no-artifacts` and MCP startup `--no-artifacts` disable persistence.

## Report shape

- Add a deterministic `## TL;DR` immediately after the title: scanned/live
  hosts, observed platform/CDN providers, tech stack, and counts of findings by
  severity. Values are computed from the JSON contract; no judgment text.
- Add hosting evidence and saved source/map links in each host section.
- Add a deterministic `## To Do` at the end, derived from actionable OPSEC
  findings only. Group duplicate titles across hosts, cite hosts and evidence
  URLs, use fixed action templates for known findings, and never imply the
  source-map exposure itself proves a vulnerability. Exclude expected client
  analytics IDs and generic fingerprintability from the checklist.

## Scope and compatibility

- Passive requests only, via the injected Fetcher and existing scope/rate
  limits. No vulnerability probing or code execution.
- Additive schema version 1.5. JSON and SQLite history remain readable. Existing
  normalized diffs include provider and content-hash changes but ignore local
  artifact paths.
- Offline fixtures cover the exact Codalio CNAME patterns, source-map
  sanitization, private permissions, size cap, first-party gating, TL;DR and
  checklist determinism, and JSON/Markdown output.
