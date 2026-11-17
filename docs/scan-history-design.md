# Progress and scan history

## Intent

Long scans should show useful live progress, keep generated files out of the
working directory, and let a user compare a domain with an earlier scan by
date. This is local-only storage; the scan JSON contract does not change.

## Approaches

- **Selected:** `~/.teardown/` holds reports, the sanitized daily HTTP cache,
  and a SQLite database of scan snapshots and per-host checkpoints. SQLite
  makes domain/date queries and interrupted-run inspection simple. Raw response
  bodies remain in the existing bounded file cache rather than inflating the
  database.
- JSON files alone would be easy to browse but need directory scans and ad hoc
  indexing for date comparisons and incomplete runs.
- Putting raw responses in SQLite would centralize storage but make one
  database large and increase the impact of retaining response bodies.

## Behavior

- Normal CLI runs save reports under `~/.teardown/reports/<domain>/` with a
  unique timestamped basename. `--out-dir` still selects a custom destination.
- CLI and MCP scans save normalized `ScanResult` JSON by default. `--no-history`
  and `teardown-mcp --no-history` disable that. `--json-only` writes only JSON to
  stdout and no report files, while still recording history unless disabled.
- Host results are checkpointed as they complete. A failed/interrupted scan
  remains marked incomplete; comparisons use complete scans only.
- `teardown history <domain>` lists saved scans. `teardown compare <domain>`
  compares the latest two completed scans; `--days N` picks the latest scan on
  or before N days before the newest scan.
- The CLI reports stages and a live host count to stderr. `-q` suppresses
  status, `-v` adds per-host details, and `-vv` adds module details. Rich colors
  are used on a terminal and disabled for plain output or `--no-color`.
- stdout remains machine readable for `--json-only`, `diff`, and JSON compare.

## Safety

The database stores the same redacted JSON as report output. The data directory
and database are private to the current user. The HTTP cache keeps its existing
secret-detection guard and daily keying. There is no authenticated scanning.
