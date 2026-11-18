# MCP server

Install the optional extra and start the server over stdio:

```bash
python -m pip install 'tech-teardown[mcp]'
teardown-mcp
```

For an MCP client that launches subprocesses, use
[`.mcp.json.example`](../.mcp.json.example). `uvx --from 'tech-teardown[mcp]'
teardown-mcp` runs it without a persistent install.

For local Streamable HTTP:

```bash
teardown-mcp --transport http --host 127.0.0.1 --port 8000
```

The endpoint is `http://127.0.0.1:8000/mcp`. Loopback is the default. If you
bind another interface, provide your own network access controls; scan tools
can reach public sites and save local results.

| Tool | Result |
| --- | --- |
| `teardown_host(url)` | One `HostTeardown` record |
| `teardown_domain(domain, max_hosts, max_probes, active_dns, use_subfinder)` | Full `ScanResult`; active DNS is opt-in |
| `enumerate_subdomains(domain, use_subfinder)` | In-scope passive host list without liveness probes |
| `scan_domain(domain, single, max_hosts, max_probes)` | Compatibility scan entry point |
| `diff_scans(old, new)` | Normalized comparison of two scan JSON objects |

Scan tools use the same collection path and limits as the CLI. MCP scans save
SQLite history and sanitized first-party artifacts by default. Start with
`--no-history`, `--no-artifacts`, or `--data-dir DIR` to change those behaviors.
