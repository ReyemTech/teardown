# Data and licenses

Teardown source code and original documentation are distributed under
[MIT](../LICENSE). The bundled fingerprint database contains OpenTechAlyzer
definitions converted from its MIT-licensed release, plus local curated
definitions. The upstream notice is included in
[`LICENSE-opentechalyzer`](../teardown/data/LICENSE-opentechalyzer) and its
provenance is recorded in [`LICENSE.md`](../teardown/data/LICENSE.md).

`teardown fingerprints update` is optional. It downloads and converts
WebAppAnalyzer's GPL-3.0 fingerprint definitions into a local user cache. That
dataset is not bundled in this repository or its wheel. Review its upstream
license before redistributing an imported database. Set
`TEARDOWN_FINGERPRINT_DB` to use a particular local copy.

GeoLite Data is created by MaxMind and is obtained at scan time through
RIPEstat; the database is not bundled. See the [collection guide](collection.md)
for attribution and limits on location inference.
