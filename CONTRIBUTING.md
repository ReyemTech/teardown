# Contributing

Thanks for helping improve Teardown. Bug reports, documentation corrections,
tests, and narrowly scoped collectors are welcome. Please keep scans bounded,
public-signal based, and free of credential collection or exploitation.

## Before opening an issue

Search existing issues and the [documentation](docs/README.md). Use a bug
report for reproducible behavior, or a feature request for an intended use and
the public signal that could support it. Do not post target secrets, raw source
maps, private domains, or personal data. Send suspected vulnerabilities through
[private reporting](SECURITY.md).

## Local setup

```bash
git clone https://github.com/ReyemTech/teardown.git
cd teardown
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[mcp]' pytest pytest-asyncio build
.venv/bin/python -m pytest -q
.venv/bin/python -m build
```

Tests use fake fetchers and must stay offline and fast. New collector tests
should cover a positive observation and a clean or failure case. Keep full
credential values out of fixtures and assertions except where a redaction
test specifically proves they do not reach the result. Read
[`AGENTS.md`](AGENTS.md) and the [development guide](docs/development.md)
before changing the JSON contract or scan behavior.

## Pull requests

1. Open a focused PR against `main` and describe the observed problem, change,
   and verification. Link the relevant issue if there is one.
2. Use a Conventional Commit subject: `fix: ...`, `feat: ...`, `docs: ...`,
   `perf: ...`, or `chore: ...`. Use an imperative summary.
3. Run the offline tests and build when changing package content. CI tests
   Python 3.10 through 3.14 and installs the built wheel.
4. Update user docs and `SCHEMA_VERSION` when changing JSON fields. Add source
   and license attribution for new datasets.

Do not include AI or Claude co-authorship trailers. Maintainers may ask for
changes, combine related commits, or defer work that expands active scanning.
By submitting a contribution, you agree to the project's [MIT License](LICENSE)
for your contribution. The [Code of Conduct](CODE_OF_CONDUCT.md) applies to
project spaces.
