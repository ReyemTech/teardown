"""Rich terminal presentation for CLI scans; never writes machine output."""

from __future__ import annotations

import sys
from typing import Any, TextIO

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from .models import ScanResult


class CliReporter:
    def __init__(self, verbosity: int = 0, quiet: bool = False,
                 no_color: bool = False, stream: TextIO | None = None) -> None:
        self.verbosity = verbosity
        self.quiet = quiet
        self.console = Console(file=stream or sys.stderr, stderr=True, no_color=no_color)
        self.progress = Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), console=self.console,
            transient=True, redirect_stdout=False, redirect_stderr=False,
            disable=not self.console.is_terminal or quiet,
        )
        self.task_id = None
        self.started = False

    def __enter__(self) -> CliReporter:
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.started:
            self.progress.stop()

    def _stage(self, label: str, total: int | None = None) -> None:
        if self.console.is_terminal and not self.quiet:
            if not self.started:
                self.progress.start()
                self.started = True
            if self.task_id is not None:
                self.progress.remove_task(self.task_id)
            self.task_id = self.progress.add_task(label, total=total)

    def __call__(self, event: str, details: dict[str, object]) -> None:
        if self.quiet:
            return
        if event == "start":
            self.console.print(f"[bold cyan]Teardown[/]  {details['target']}")
            self._stage("Enumerating public sources")
        elif event == "source" and self.verbosity:
            self.console.print(f"  [dim]{details['source']}[/]  {details['count']} hosts so far")
        elif event == "enumerated":
            self.console.print(f"[green]Found[/] {details['count']} candidate hosts")
        elif event == "probe":
            if self.task_id is None or self.progress.tasks[0].description != "Checking liveness":
                self._stage("Checking liveness", int(details["total"]))
            if self.task_id is not None:
                self.progress.update(self.task_id, completed=int(details["done"]))
            if self.verbosity >= 2:
                state = "live" if details["reachable"] else "unreachable"
                self.console.print(f"  {details['host']}  [dim]{state}[/]")
        elif event == "live":
            self.console.print(f"[green]Live[/] {details['count']} / {details['found']} hosts")
            self._stage("Analyzing hosts", int(details["count"]))
        elif event == "host_start" and self.verbosity >= 2:
            self.console.print(f"  [cyan]{details['host']}[/]  started")
        elif event == "module" and self.verbosity >= 2:
            status = "done" if details["success"] else "failed"
            self.console.print(f"    [dim]{details['module']}[/]  {status}")
        elif event == "host_done":
            if self.task_id is not None:
                self.progress.update(self.task_id, completed=int(details["done"]))
            if self.verbosity:
                self.console.print(
                    f"  [cyan]{details['host']}[/]  "
                    f"{details['findings']} findings")
        elif event == "finished" and self.started:
            self.progress.stop()
            self.started = False
            self.task_id = None

    def summary(self, result: ScanResult, paths: dict[str, str] | None = None) -> None:
        if self.quiet:
            return
        table = Table(title="Scan complete", show_header=False, box=None)
        table.add_column(style="bold cyan")
        table.add_column()
        table.add_row("Domain", result.root_domain)
        table.add_row("Hosts", str(len(result.hosts)))
        table.add_row("Live / found", f"{result.enumeration.live_hosts} / "
                      f"{result.enumeration.subdomains_found}")
        table.add_row("Critical findings", str(len(result.aggregate.critical_findings)))
        networks = [entry for host in result.hosts for entry in host.network.addresses
                    if entry.prefix or entry.asns]
        if networks:
            first = networks[0]
            asn = ", ".join(f"AS{number}" for number in first.asns) or "unknown ASN"
            table.add_row("Observed network", f"{asn} · {first.prefix or 'unknown prefix'}")
        if paths:
            table.add_row("JSON", paths["json"])
            table.add_row("Markdown", paths["md"])
        self.console.print(table)


def print_history(domain: str, scans: list[dict[str, Any]],
                  no_color: bool = False) -> None:
    console = Console(no_color=no_color)
    table = Table(title=f"Scan history · {domain}")
    table.add_column("Scanned (UTC)", style="cyan")
    table.add_column("Status")
    table.add_column("Hosts", justify="right")
    table.add_column("Scan ID", style="dim")
    for scan in scans:
        table.add_row(scan["started_at"], scan["status"],
                      str(scan["host_count"]), scan["id"][:12])
    console.print(table if scans else f"No saved scans for {domain}.")


def print_comparison(comparison: dict[str, Any], no_color: bool = False) -> None:
    console = Console(no_color=no_color)
    diff = comparison["diff"]
    console.print(f"[bold cyan]Comparison[/]  {comparison['root_domain']}")
    console.print(f"  {comparison['old_scanned_at']}  →  {comparison['new_scanned_at']}")
    table = Table(show_header=False, box=None)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Added hosts", ", ".join(diff["added_hosts"]) or "—")
    table.add_row("Removed hosts", ", ".join(diff["removed_hosts"]) or "—")
    table.add_row("Changed hosts", str(len(diff["changed_hosts"])))
    console.print(table)
    for host in diff["changed_hosts"]:
        changes = Table(title=host["host"], show_lines=False)
        changes.add_column("Signal", style="cyan")
        changes.add_column("Before")
        changes.add_column("After")
        for item in host["changes"]:
            changes.add_row(item["path"], _compact(item["before"]),
                            _compact(item["after"]))
        console.print(changes)


def _compact(value: Any) -> str:
    import json
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return rendered if len(rendered) <= 100 else rendered[:97] + "…"
