# Source-map intelligence design

## Intent

Explain what a publicly reachable first-party source map contains, with bounded,
deterministic evidence. Codalio's saved map has 41 embedded sources: 39 dependency
paths and 2 application paths. One application source contains an OpenAPI 3.0.3
object with 88 paths, 200 HTTP operations, and 36 schemas. The current report
shows only the number 41.

## Approaches

- **Compact report, structured JSON:** summarize source categories, embedded
  content, route references, and embedded API schema counts in Markdown; keep
  bounded path samples in JSON. This minimizes report length.
- **Full Markdown appendix (chosen):** list source paths and embedded OpenAPI
  paths/methods in the report, with explicit caps. The user prefers detail they
  can inspect directly in Markdown.
- **Counts only:** small and safe, but misses the useful embedded API schema.

## Rules

- Analyze existing fetched source-map responses in memory. No additional
  requests, code execution, route probing, or dependency CVE assertions. Do not
  test all referenced paths; the spec includes modifying HTTP methods, and even
  a GET can have application side effects. Mark paths as references only.
- Analyze first-party maps only. Keep third-party maps out of host risk claims.
- Parse `sourcesContent` when present; distinguish application and dependency
  paths. A map without `sourcesContent` reveals paths but not original bodies.
- Detect JSON-formatted OpenAPI objects embedded in original source, including
  `const name = { ... }`. Report path, method, and component-schema counts with
  bounded route samples. Label them *referenced*, not verified reachable.
- Keep report and JSON free of raw source text, secret values, and unbounded path
  lists. Cap source and API-path inventories at 200 each, stating when truncated.
  Apply existing redaction before extracting values. Do not treat absent
  OpenAPI security declarations as evidence that authorization is missing.
- Use OWASP WSTG-INFO-05 and WSTG-APIT-03 as review references, not automatic
  proof of an OWASP Top Ten vulnerability. Preserve existing Medium source-map
  severity unless a separate validated finding warrants otherwise.
- Additive schema 1.6; normalized diffs may show meaningful intel changes.

## Output

`Bundle.source_map_intel` contains source counts, bounded application and
dependency path inventories, referenced routes, and optional embedded OpenAPI
summary. Markdown gives a short summary followed by the bounded source and
OpenAPI path/method inventory, and says that route names and spec declarations
do not establish live authorization behavior. The To Do section stays last.
README explains what to inspect next and the limits of passive evidence.
