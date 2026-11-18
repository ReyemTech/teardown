# Implementation plan

> Historical implementation plan. Start with the [maintained guides](README.md)
> for current behavior.

1. Write offline regression tests for Astro assets, Fastly headers, and current
   `stint.reyem.tech` style responses. Verify red against the merged version.
2. Merge curated rules with upstream definitions and parse stylesheet sources.
   Add Astro asset rules and fix Fastly liveness metadata.
3. Add `ScanContext`, named built-in modules, and a small registration interface.
   Add `HostTeardown.extensions` and bump schema to 1.2.
4. Refactor `teardown_host` to run modules independently; keep the existing
   public function signatures and Fetcher injection. Add plugin and failure
   tests, then update README and AGENTS.
5. Run offline tests and build, scan the public host once more, open and merge
   the follow-up PR, then attempt PyPI publication from the verified main tree.
