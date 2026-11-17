# Passive intelligence expansion

The scanner remains a deterministic collector of public frontend evidence. This
increment adds a local fingerprint database, optional upstream import, passive
enumeration plugins, reusable response cache, and a stable cross-run diff.

1. Match the built-in MIT-licensed OpenTechAlyzer fingerprint JSON against the
   signals already present in response headers, cookies, HTML, meta tags,
   script URLs, and the final URL. Expose each match with redacted evidence and a
   deterministic confidence score. Keep legacy `frameworks` and `cms` fields
   derived from matches for existing readers. A user-invoked update command
   downloads WebAppAnalyzer's GPL-3.0 dataset into the user's local cache; the
   repository and wheel never redistribute that dataset.
2. Add FastMCP as an optional package extra. Tools call the existing scan and
   diff functions; stdio is the default transport. No separate request path.
3. Model passive sources behind one interface. Use crt.sh and keyless archive
   sources by default, with optional installed subfinder. All results pass the
   existing root-domain scope filter. Reuse the liveness response for the host
   collection, recording title, status chain, TLS and CDN signals.
4. Cache bounded, sanitized GET responses by URL and UTC day. Never persist
   credentials or unredacted secret values. Cache hits still pass through the
   same collectors. A rerun can resume from cached responses; no incomplete
   scan result is treated as complete.
5. Emit schema 1.1 with additive fields. A pure diff command compares stable
   host records and signals, excluding scan timestamps and volatile response
   headers. Results have deterministic order and machine-readable changes.

The Python test suite stays offline. Fake Fetchers cover source parsing, cache
behavior, liveness reuse, fingerprint evidence, and diff normalization. The
optional FastMCP extra gets an in-process smoke test if installed.
