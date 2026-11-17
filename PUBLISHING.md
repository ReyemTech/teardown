# Publishing

The PyPI distribution is `tech-teardown`, with `tech-teardown` and `teardown`
console commands. It builds with
hatchling and publishes from GitHub Actions through PyPI trusted publishing.

## 1. Use Conventional Commits

Merge a PR into `main` with a Conventional Commit subject. Python Semantic
Release reads commits since the previous `v<version>` tag: `fix:` and `perf:`
bump patch, `feat:` bumps minor, and a breaking change bumps major. Other
types such as `docs:` and `chore:` do not publish by themselves. It updates
`pyproject.toml`, creates the version tag and GitHub release, and writes the
changelog. Do not edit the version by hand.

## 2. Build locally when needed

```bash
uv build --out-dir dist-release
# -> dist-release/tech_teardown-<version>-py3-none-any.whl
#    dist-release/tech_teardown-<version>.tar.gz
```

Sanity-check a built artifact:

```bash
uvx --from dist-release/tech_teardown-<version>-py3-none-any.whl teardown example.com --single --json-only
```

## 3. PyPI trusted publisher

The [trusted publisher](https://docs.pypi.org/trusted-publishers/)
is configured in PyPI with these fields:

| Field | Value |
|-------|-------|
| PyPI project | `tech-teardown` |
| GitHub owner | `ReyemTech` |
| Repository | `teardown` |
| Workflow filename | `release.yml` |
| Environment | leave blank |

No long-lived token is needed in the repository or workflow.

## 4. Publish to PyPI

Merging into `main` starts `.github/workflows/release.yml`. It tests the
merged commit, calculates a release, builds the distributions, and publishes
with GitHub OIDC when a new version was created. The publish job has PyPI
access; the version job has GitHub contents write access.

## 5. After publish

Once live, anyone can run it with no install:

```bash
uvx tech-teardown example.com --single
```

## Notes

- `requires-python = ">=3.10"`.
- Runtime deps: `httpx` and `tldextract` (using its bundled public suffix list).
  `dnspython` is an optional extra (`tech-teardown[active-dns]`),
  only needed for `--active-dns`. FastMCP is an optional extra (`tech-teardown[mcp]`).
- PR CI runs tests on Python 3.10–3.14, builds distributions, and checks both
  CLI names from the installed wheel. The release workflow retests on `main`.
