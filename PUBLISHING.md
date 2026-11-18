# Publishing `tech-teardown`

The PyPI distribution is `tech-teardown`. Its installed commands are
`tech-teardown`, `teardown`, and, with the MCP extra, `teardown-mcp`.
Hatchling builds the package; GitHub Actions publishes through PyPI trusted
publishing. The latest version is recorded in `pyproject.toml` and
[`CHANGELOG.md`](CHANGELOG.md).

## Normal release

Merge a PR to `main` with a Conventional Commit subject. `fix:` and `perf:`
produce patch releases, `feat:` produces a minor release, and a breaking
change produces a major release under the semantic-release configuration.
The release workflow tests the merged commit, calculates the next version,
updates `pyproject.toml` and `CHANGELOG.md`, creates a `v<version>` tag and
GitHub release, builds distributions, then publishes to PyPI through OIDC.
Do not edit the version or tag by hand.

The `main` push trigger uses GitHub `paths-ignore`: a merge containing only
Markdown, `docs/**` assets, `LICENSE`, or issue/PR templates does **not start**
the release workflow. A merge containing any other path does start it; semantic
release then decides whether a version is warranted. PR CI runs independently
of this filter. Keep the release workflow out of required PR checks because a
path-filtered workflow can otherwise leave a required check pending.

## Trusted publisher

The [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/) is
configured for project `tech-teardown`, GitHub owner `ReyemTech`, repository
`teardown`, workflow `release.yml`, and no environment. The publish job has
`id-token: write`; no repository PyPI token is required.

## Verify an artifact locally

```bash
uv build --out-dir dist-release
uvx --from dist-release/tech_teardown-<version>-py3-none-any.whl teardown --help
```

The source distribution and wheel should include the project MIT license and
the bundled OpenTechAlyzer MIT notice. Run the offline tests before merging:
`.venv/bin/python -m pytest -q`.

## Recover a failed publish

If a version tag exists but publishing failed, inspect the failed run and
confirm the tag and PyPI state first. Manually dispatch `Release to PyPI` with
the existing numeric version, for example `0.6.0`. The recovery job checks
out `v<version>`, builds that tagged source, publishes it, and creates the
GitHub release. It accepts an existing tag; it does not calculate a new
version. Do not dispatch it for a version already present on PyPI.

## Dependencies and compatibility

Python 3.10+ is supported. Core dependencies are `httpx`, `tldextract`,
`rich`, and `dnspython`. The `active-dns` extra remains for compatibility,
but the wordlist DNS path is controlled by `--active-dns`, not by installing
an extra. `tech-teardown[mcp]` adds FastMCP. PR CI tests Python 3.10–3.14 and
smoke-tests the installed wheel's CLI entry points.
