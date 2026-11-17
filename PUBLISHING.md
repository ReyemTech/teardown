# Publishing

The package and console command are both `teardown`. It builds with
hatchling and publishes with `uv`.

## 1. Bump the version

Edit `version` in `pyproject.toml` (semver). A PyPI version can only be uploaded
once — never reuse a number.

## 2. Build

```bash
uv build --out-dir dist-release
# -> dist-release/teardown-<version>-py3-none-any.whl
#    dist-release/teardown-<version>.tar.gz
```

Sanity-check the built artifact before publishing:

```bash
uvx --from dist-release/teardown-<version>-py3-none-any.whl teardown example.com --single --json-only
```

## 3. Publish to PyPI

Create a PyPI API token (https://pypi.org/manage/account/token/), then:

```bash
uv publish --token pypi-<your-token> dist-release/teardown-*
# or export UV_PUBLISH_TOKEN=pypi-<token>  &&  uv publish dist-release/teardown-*
```

Test against TestPyPI first if you want a dry run:

```bash
uv publish --publish-url https://test.pypi.org/legacy/ --token <testpypi-token> dist-release/teardown-*
```

## 4. After publish

Once live, anyone can run it with no install:

```bash
uvx teardown example.com --single
```

Tag the release:

```bash
git tag v<version> && git push origin v<version>
```

## Notes

- `requires-python = ">=3.10"`.
- Runtime deps: `httpx` and `tldextract` (using its bundled public suffix list).
  `dnspython` is an optional extra (`teardown[active-dns]`),
  only needed for `--active-dns`. FastMCP is an optional extra (`teardown[mcp]`).
- CI runs tests on Python 3.10–3.14, builds distributions, and checks the
  installed wheel's CLI. Publishing remains manual with `uv publish`.
