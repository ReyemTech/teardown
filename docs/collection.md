# Collection and interpretation

Teardown collects deterministic signals from publicly accessible pages and
services. It does not authenticate, exploit, evade defenses, or turn source-map
references into a path-testing campaign. Use it only on targets you are
authorized to assess and respect the target's terms and rate limits.

## Scope and limits

The target is reduced to its registrable root using a bundled public suffix
list, including private suffixes. Passive enumeration queries crt.sh,
CertSpotter, and Wayback; installed `subfinder` is optional. Wordlist DNS
enumeration requires `--active-dns`. Found hosts are scope-filtered, liveness
checks are bounded, and redirects outside the root are not followed. The
HTTP client applies a global concurrency cap, rate limit, retries, and an
identifying user agent. Third-party asset URLs can be listed as evidence;
their bodies are not fetched as first-party bundles.

## What evidence means

| Signal | Safe reading |
| --- | --- |
| Technology detection | A passive fingerprint matched the listed header, cookie name, markup, or asset signal. Confidence is deterministic signal strength, not a calibrated probability. |
| API response | An observed response supports a specific API claim. An HTML fallback does not establish an API. |
| Source-map API path | A path is referenced in shipped frontend material. It may be stale, unreachable, or protected. Teardown does not probe every path or execute methods from embedded specs. |
| Source-map exposure | Original source paths or content may be available. Exposure alone does not prove a secret, exploit, or missing authorization. |
| DNS address and ASN | An observed address, routed prefix, or registered holder. These can identify a CDN edge or infrastructure provider, not the application's operator or origin. |
| Provider CNAME | A provider-owned DNS target supports a hosting or routing label. An AWS ELB name does not by itself prove Elastic Beanstalk. |
| Geo-IP | An approximate database estimate for an observed address. A CDN edge estimate is not the origin or a precise server location. |

The Geo-IP data is GeoLite Data created by MaxMind, available from
[MaxMind](https://www.maxmind.com), through the
[RIPEstat MaxMind GeoLite endpoint](https://stat.ripe.net/docs/data-api/api-endpoints/maxmind-geo-lite).
Unknown locations are omitted. Network route and registration data also comes
from RIPEstat; DNS answers can differ by resolver and scan time.

## Findings and review

Findings cite the evidence that triggered a rule. First-party source maps are
reported at medium severity for review; maps published by unrelated CDNs are
not attributed to the target. Recognizable credentials are redacted in output.
The report's task list is a mechanical list of follow-ups, not a claim that
each item is exploitable. Human review should confirm exposure, impact,
ownership, and permission before any further testing. For source and API
review context, see OWASP
[WSTG-INFO-05](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage/)
and [WSTG-APIT-03](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure/).
