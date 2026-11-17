"""Optional FastMCP stdio interface around the existing scan contract."""

from __future__ import annotations

import argparse

from .cli import run_scan
from .models import to_dict


def create_server():
    try:
        from fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("Install reyem-teardown[mcp] to run the MCP server") from exc

    server = FastMCP("reyem-teardown")

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
