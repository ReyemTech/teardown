# Output and local storage

The machine output is a `ScanResult` with `schema_version` and one
`HostTeardown` per scanned host. Schema 1.6 is defined by the dataclasses in
[`models.py`](../teardown/models.py). Consumers should check `schema_version`,
use documented fields rather than parsing Markdown, and tolerate absent
optional observations. Renaming or reshaping a field requires a schema bump.

For each ordinary scan, Teardown writes a timestamped `*-teardown.json` and
`*-teardown.md` under `~/.teardown/reports/<domain>/`. The Markdown report has
an observed-signal summary, per-host evidence, findings, a bounded full
source-map appendix, and a mechanical task list. It does not make an overall
security judgment. `--json-only` writes JSON to stdout instead of report files.

## History, cache, and artifacts

- `history.sqlite3` stores completed scans and per-host checkpoints so
  interrupted work can be inspected and runs compared.
- `cache/` stores safe GET responses by URL and UTC day. Responses with
  sensitive-looking content are not cached; cookie values are never stored.
- `artifacts/` stores sanitized, content-addressed copies of first-party JS
  bundles and valid exposed source maps, subject to a 4 MB limit per file.
  Artifact references in JSON include local paths and SHA-256 hashes. Embedded
  `sourcesContent` can include application logic and should be handled as
  sensitive material even after recognized credentials are redacted.

The default data home is `~/.teardown`; override it with `--data-dir` or
`TEARDOWN_HOME`. Report location can be changed separately with `--out-dir`.
Disable the stores per scan with `--no-cache`, `--no-history`, and
`--no-artifacts`. These settings also apply to MCP scans through its startup
flags where supported.

## Sharing results

Teardown masks recognized credential patterns, secret-bearing headers, and
sensitive URL query values. Public pages may contain other personal or
confidential information. Review JSON, Markdown, history exports, and saved
artifacts before sharing them. Do not attach raw target responses or source
maps to public issues; follow [SECURITY.md](../SECURITY.md) for sensitive
reports. Report files are local scan records, not part of the package.
