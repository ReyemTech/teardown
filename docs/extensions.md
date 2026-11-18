# Extending Teardown

## Scan modules

Built-in modules collect HTTP, network, fingerprint, bundle, third-party,
secret, and API signals. To append an in-process module, register a
`ScanModule` before calling `run_scan`:

```python
from teardown.scan_modules import ScanModule, register_module

async def collect(context):
    # Use context.fetcher for bounded, in-scope requests.
    return {"public_marker": "observed"}

register_module(ScanModule("example", collect))
```

The returned JSON mapping appears at `hosts[].extensions.example`. Names use
lowercase letters, digits, and underscores; duplicate names are rejected.
The module runner isolates failures so later modules still run. The extension
payload is sanitized, but module authors must avoid collecting secrets in the
first place. Never create raw `httpx` clients inside a collector: injected
`Fetcher` preserves scope, politeness, and offline testability. A scan may
select modules with `run_scan(..., modules=[...])`.

## Fingerprints

Add local technology rules to [`curated.json`](../teardown/data/curated.json).
The bundled MIT database is generated from OpenTechAlyzer by
[`update_builtin_fingerprints.mjs`](../scripts/update_builtin_fingerprints.mjs).
The optional WebAppAnalyzer import is downloaded by the user with `teardown
fingerprints update`; `TEARDOWN_FINGERPRINT_DB` selects a local converted file.
The imported definitions update bundled names, and curated definitions take
final precedence. See [data licensing](data.md).

Third-party and secret patterns live in
[`html_js.py`](../teardown/collectors/html_js.py). New secret patterns must
redact values and have a test showing the full value never appears in output.
New findings belong in [`analyze.py`](../teardown/analyze.py) and should cite
the triggering signal and remain absent on a clean host. JSON field changes
require a `SCHEMA_VERSION` bump and consumer review.
