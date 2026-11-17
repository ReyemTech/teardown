# Publishing

The PyPI distribution is `tech-teardown` and the console command is `teardown`. It builds with
hatchling and publishes from GitHub Actions through PyPI trusted publishing.

## 1. Bump the version

Edit `version` in `pyproject.toml` (semver). A PyPI version can only be uploaded
once — never reuse a number.

## 2. Build

```bash
uv build --out-dir dist-release
# -> dist-release/tech_teardown-<version>-py3-none-any.whl
#    dist-release/tech_teardown-<version>.tar.gz
```

Sanity-check the built artifact before publishing:

```bash
uvx --from dist-release/tech_teardown-<version>-py3-none-any.whl teardown example.com --single --json-only
```

## 3. Configure PyPI once

For the first release, add a [pending trusted publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
in your PyPI account with these exact fields:

| Field | Value |
|-------|-------|
| PyPI project | `tech-teardown` |
| GitHub owner | `ReyemTech` |
| Repository | `teardown` |
| Workflow filename | `release.yml` |
| Environment | leave blank |

PyPI converts the pending publisher to a normal publisher on first upload. No
long-lived token is needed in the repository or workflow.

## 4. Publish to PyPI

Tag the verified `main` commit. The tag starts the release workflow, which
reruns tests, builds both distributions, and publishes with GitHub OIDC:

```bash
git tag -a v<version> -m v<version>
git push origin v<version>
```

## 5. After publish

Once live, anyone can run it with no install:

```bash
uvx --from tech-teardown teardown example.com --single
```

## Notes

- `requires-python = ">=3.10"`.
- Runtime deps: `httpx` and `tldextract` (using its bundled public suffix list).
  `dnspython` is an optional extra (`tech-teardown[active-dns]`),
  only needed for `--active-dns`. FastMCP is an optional extra (`tech-teardown[mcp]`).
- CI runs tests on Python 3.10–3.14, builds distributions, and checks the
  installed wheel's CLI. `.github/workflows/release.yml` publishes only on
  version tags after its build and test job succeeds.
