# Publishing

The package is `reyem-teardown` (console command: `teardown`). It builds with
hatchling and publishes with `uv`.

## 1. Bump the version

Edit `version` in `pyproject.toml` (semver). A PyPI version can only be uploaded
once — never reuse a number.

## 2. Build

```bash
uv build
# -> dist/reyem_teardown-<version>-py3-none-any.whl
#    dist/reyem_teardown-<version>.tar.gz
```

Sanity-check the built artifact before publishing:

```bash
uvx --from dist/reyem_teardown-<version>-py3-none-any.whl teardown example.com --single --json-only
```

## 3. Publish to PyPI

Create a PyPI API token (https://pypi.org/manage/account/token/), then:

```bash
uv publish --token pypi-<your-token>
# or export UV_PUBLISH_TOKEN=pypi-<token>  &&  uv publish
```

Test against TestPyPI first if you want a dry run:

```bash
uv publish --publish-url https://test.pypi.org/legacy/ --token <testpypi-token>
```

## 4. After publish

Once live, anyone can run it with no install:

```bash
uvx reyem-teardown example.com --single
```

Tag the release:

```bash
git tag v<version> && git push origin v<version>
```

## Notes

- `requires-python = ">=3.10"`.
- Runtime dep: `httpx`. `dnspython` is an optional extra (`reyem-teardown[active-dns]`),
  only needed for `--active-dns`.
- No PyPI trusted-publishing / CI release workflow is set up yet; this is a manual
  `uv publish`. Add a GitHub Actions release job later if you want it automated.
