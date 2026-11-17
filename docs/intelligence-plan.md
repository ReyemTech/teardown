# Implementation plan

1. Add schema fields for detections, confidence, liveness and redirect/TLS
   metadata. Write tests for their serialization and evidence redaction.
2. Convert the MIT upstream fingerprint definitions into bundled JSON with
   attribution. Build a pure matcher and optional WebAppAnalyzer importer with
   offline tests, then wire detections into host scans.
3. Add the optional FastMCP entry point and offline tool tests.
4. Add passive source adapters and optional subfinder. Test parsing, scope and
   failure isolation. Reuse liveness responses and enrich `HttpInfo`.
5. Add a sanitized daily response cache and CLI controls. Test hit/miss,
   redaction, expiration and resume behavior.
6. Add normalized diff and CLI command. Test deterministic output and changes.
7. Update README and package metadata. Run the full offline suite, package
   build and installed-wheel smoke tests, then review the diff and commit.
