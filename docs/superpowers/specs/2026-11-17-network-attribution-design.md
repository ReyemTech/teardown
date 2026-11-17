# Network attribution design

## Intent

Show where a scanned hostname resolves and which network announces its address.
Give an agent evidence to distinguish CDN edge infrastructure from a possible
direct endpoint. Do not claim to discover an origin behind a CDN.

## Approaches

1. **ASN and prefix only:** small and quick, but misses DNS indirection and
   registration data. Rejected because it leaves the hosting story ambiguous.
2. **DNS, routing, and registered holder:** selected. Resolve A, AAAA, and a
   bounded CNAME chain; look up routed prefix and ASN in RIPEstat; read public
   network registration data. This adds a few bounded, cacheable lookups.

## Contract and behavior

- Add `HostTeardown.network` and bump the additive JSON contract to schema 1.3.
  Include resolved addresses, CNAME chain, per-address routed prefix, all
  announced ASNs and holders, registered network holder/name when available,
  and source labels. Keep IPv4 and IPv6 separate. Limit to eight IPs and eight
  CNAME hops per host; record truncation and lookup errors without failing a scan.
- Label the observation as `cdn_edge` when existing CDN evidence is present,
  otherwise `observed_endpoint`. Neither label claims origin discovery.
- Run attribution as a built-in named host module. Use an injected DNS resolver
  and the existing `Fetcher` for HTTP; do not create a raw HTTP client in a
  collector. Allow only the three specific RIPEstat API paths in `HttpClient`.
- Use system DNS via `dnspython` with bounded timeouts. The DNS query is for the
  host already being scanned; no wordlist or expanded scan scope.
- Include network data in Markdown. Existing normalized diff and SQLite history
  compare the new fields automatically. The terminal summary may show the
  primary ASN and prefix but must not infer geography or origin.

## Limits

- DNS answers vary by resolver, location, and time. The resolved address may
  differ from the HTTP connection's peer; label it as a DNS observation.
- Routing and registration records can lag or be incomplete. Missing values
  stay null or empty. A registered holder is not necessarily the app operator.
- RIPEstat lookups use the existing daily sanitized cache. No geolocation,
  traceroute, origin hunting, or active probing beyond the existing scan.

## Verification

Offline tests cover A/AAAA and CNAME normalization, multi-origin prefixes,
registry field variants, CDN edge labeling, missing/failed lookups, scope and
rate-limit routing, JSON/Markdown, and historical diff. Full test and wheel
build gates remain required.
