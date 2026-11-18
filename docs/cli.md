# CLI guide

## Install

Python 3.10+ is required. Run `uvx tech-teardown --help` without a persistent
installation, or install with `python -m pip install tech-teardown`. The PyPI
distribution installs both `tech-teardown` and `teardown` commands.

For a checkout, run `python -m pip install -e '.[mcp]'` in a virtual environment.
The `active-dns` extra remains available for compatibility, although DNS is a
core dependency for network attribution; `--active-dns` still controls wordlist
enumeration.

## Scan modes

```bash
teardown example.com --single          # only this host
teardown example.com                   # passive subdomain discovery
teardown example.com --subfinder       # add installed subfinder's passive sources
teardown example.com --active-dns --wordlist words.txt
teardown example.com --max-probes 40 --max-hosts 10
teardown example.com -v                # per-host progress
teardown example.com -vv               # module and probe progress
teardown example.com --json-only       # JSON stdout, no report files
```

The default limits are 100 liveness probes, 25 live hosts torn down, 10
concurrent requests, and eight requests per second. `--max-probes 0` and
`--max-hosts 0` remove those respective caps; concurrency and rate still apply.
`--single` skips enumeration. A target may be a domain or URL. See `teardown
--help` for the complete option list.

Status and progress use stderr. `-q` suppresses status, `--no-color` disables
styling, and `--json-only` keeps stdout machine-readable. An ordinary scan
writes two report files; `--json-only` skips them but still saves SQLite history
unless `--no-history` is set.

## Data locations and controls

`--data-dir DIR` (or `TEARDOWN_HOME`) sets the data home; its default is
`~/.teardown`. `--out-dir DIR` changes only the report location. `--name NAME`
sets the report basename. `--cache-dir DIR` changes the response cache location.
Use `--no-cache`, `--no-history`, or `--no-artifacts` to disable each store for
a scan. Local data is intended to be private to the user on Unix.

## History and comparison

```bash
teardown history example.com
teardown history example.com --limit 50 --json
teardown compare example.com
teardown compare example.com --days 7 --json
teardown diff old.json new.json
```

`history` lists completed and interrupted scans, including host checkpoint
counts. `compare` uses the latest completed scan and the previous completed
scan, or with `--days N`, the newest completed baseline at least N days older.
`diff` compares two saved JSON records directly. Time stamps and volatile HTTP
headers are excluded from the normalized comparison.

## Fingerprint database

The bundled MIT database works without a separate download. To import the
larger community-maintained dataset into your local cache, run `teardown
fingerprints update`. This is an optional network operation and imports data
under its own license. See [data licensing](data.md).
