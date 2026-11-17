"""Optional FastMCP stdio interface around the existing scan contract."""

from __future__ import annotations

import argparse

from .cli import run_scan
from .models import to_dict


def create_server():
    try:
        from fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("Install teardown[mcp] to run the MCP server") from exc

    server = FastMCP("teardown")

    @server.tool
    async def teardown_host(url: str) -> dict:
        """Collect public frontend signals for one host."""
        result = await run_scan(url, single=True, active_dns=False, wordlist=None,
                                max_hosts=1, max_probes=1, concurrency=10,
                                rate_per_sec=8.0)
        return to_dict(result.hosts[0])

    @server.tool
    async def teardown_domain(domain: str, max_hosts: int = 25, max_probes: int = 100,
                              active_dns: bool = False, use_subfinder: bool = False) -> dict:
        """Collect a full domain ScanResult; active DNS is opt-in."""
        result = await run_scan(domain, single=False, active_dns=active_dns, wordlist=None,
                                max_hosts=max_hosts, max_probes=max_probes,
                                concurrency=10, rate_per_sec=8.0,
                                use_subfinder=use_subfinder)
        return to_dict(result)

    @server.tool
    async def enumerate_subdomains(domain: str, use_subfinder: bool = False) -> dict:
        """List in-scope hosts from passive sources without liveness probes."""
        from .cli import _normalize
        from .enumerate import enumerate_subdomains as collect_subdomains
        from .http_client import HttpClient
        _url, _host, root = _normalize(domain)
        async with HttpClient(root_domain=root) as client:
            hosts, info = await collect_subdomains(root, client,
                                                  use_subfinder=use_subfinder)
        return {"hosts": hosts, "enumeration": to_dict(info)}

    @server.tool
    async def scan_domain(domain: str, single: bool = False, max_hosts: int = 25,
                          max_probes: int = 100) -> dict:
        """Collect public frontend signals for a domain with bounded passive scanning."""
        result = await run_scan(domain, single=single, active_dns=False, wordlist=None,
                                max_hosts=max_hosts, max_probes=max_probes,
                                concurrency=10, rate_per_sec=8.0)
        return to_dict(result)

    @server.tool
    def diff_scans(old: dict, new: dict) -> dict:
        """Compare two ScanResult JSON objects by normalized host signals."""
        from .diff import diff_results
        return diff_results(old, new)

    return server


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="teardown-mcp")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = create_server()
    if args.transport == "http":
        server.run(transport="http", host=args.host, port=args.port)
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
