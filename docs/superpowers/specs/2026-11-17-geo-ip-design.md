# Geo-IP attribution design

## Intent

Add approximate geographical context to each public IP address already
resolved by network attribution. A location describes a database estimate for
an address, which may be a CDN edge; it does not identify a server, origin, or
operator's physical location.

## Approach

Use RIPEstat's MaxMind GeoLite endpoint for each global address through the
existing `Fetcher` and daily sanitized response cache. This shares the
existing request limits and adds one bounded query per address. A local GeoIP
database would add update and license-key maintenance; an unrelated public
API would add another provider and privacy boundary.

## Contract

- Add optional `NetworkAddress.geo` with country code, city, coordinates when
  meaningful, source `MaxMind GeoLite2 via RIPEstat`, and data timestamp.
- Bump additive `SCHEMA_VERSION` from 1.3 to 1.4. Existing normalized diff and
  SQLite history compare the new field without migrations.
- Treat `?`, empty names, invalid coordinates, and `(0, 0)` placeholders as
  unknown. Do not turn a missing lookup into an invented country or city.
- Continue to skip external lookup for non-global IP addresses. Geo lookup
  failure remains a per-address error and does not discard routing evidence.
- Show country and city in the Markdown network table, alongside a clear
  approximation and CDN-edge caveat. Include MaxMind attribution in reports
  and README. Coordinates remain in JSON only, with no precise-location claim.

## Verification

Offline fixtures cover a known country/city, unknown placeholders, malformed
responses, source failure, private IPs, HTTP allowlist, JSON/Markdown, and diff.
Run the full test matrix and package build before release.
