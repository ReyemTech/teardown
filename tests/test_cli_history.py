"""CLI and MCP storage behavior with an offline HTTP client."""

from __future__ import annotations

import json

import pytest

from teardown.cli import main, run_scan
from teardown.history import HistoryStore
from teardown.http_client import FetchResponse


class OfflineClient:
    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        pass

    async def get(self, url, **_kwargs):
        if url == "https://example.com":
            return FetchResponse(url=url, final_url=url, status=200,
                                 text="<title>Example</title>")
        return FetchResponse(url=url, final_url=url, status=None)

    async def request(self, _method, url, **kwargs):
        return await self.get(url, **kwargs)


@pytest.mark.asyncio
async def test_run_scan_checkpoints_and_emits_progress(tmp_path, monkeypatch):
    monkeypatch.setattr("teardown.cli.HttpClient", OfflineClient)
    events = []
    with HistoryStore(tmp_path) as history:
        result = await run_scan(
            "example.com", single=True, active_dns=False, wordlist=None,
            max_hosts=1, concurrency=1, rate_per_sec=8, data_dir=str(tmp_path),
            history=history, on_event=lambda event, info: events.append((event, info)),
        )
        assert history.list_scans("example.com")[0]["status"] == "complete"
        assert history.list_scans("example.com")[0]["host_count"] == 1
        assert history.latest_result("example.com")["hosts"][0]["http"]["title"] == "Example"
    assert result.hosts[0].reachable
    assert {event for event, _ in events} >= {"start", "live", "host_start", "module", "host_done", "finished"}


def test_cli_json_stdout_history_and_opt_out(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("teardown.cli.HttpClient", OfflineClient)
    monkeypatch.setenv("TEARDOWN_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    assert main(["example.com", "--single", "--json-only"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["root_domain"] == "example.com"
    assert "Scan complete" in output.err
    assert not list(tmp_path.glob("*-teardown.json"))
    with HistoryStore(tmp_path / "home") as history:
        assert len(history.list_scans("example.com")) == 1

    assert main(["example.com", "--single", "--json-only", "--quiet", "--no-history"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["root_domain"] == "example.com"
    assert output.err == ""
    with HistoryStore(tmp_path / "home") as history:
        assert len(history.list_scans("example.com")) == 1


def test_cli_default_report_location_and_history_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("teardown.cli.HttpClient", OfflineClient)
    monkeypatch.setenv("TEARDOWN_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    assert main(["example.com", "--single", "--no-color"]) == 0
    assert main(["example.com", "--single", "--no-color"]) == 0
    reports = list((tmp_path / "home" / "reports" / "example.com").glob("*.json"))
    assert len(reports) == 2
    assert not list(tmp_path.glob("*-teardown.json"))
    capsys.readouterr()

    assert main(["history", "example.com", "--json"]) == 0
    scans = json.loads(capsys.readouterr().out)
    assert len(scans) == 2
    assert main(["compare", "example.com", "--json"]) == 0
    comparison = json.loads(capsys.readouterr().out)
    assert comparison["root_domain"] == "example.com"
    assert comparison["diff"]["added_hosts"] == []


def test_verbose_status_stays_on_stderr(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("teardown.cli.HttpClient", OfflineClient)
    assert main(["example.com", "--single", "--json-only", "-vv",
                 "--data-dir", str(tmp_path)]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["root_domain"] == "example.com"
    assert "example.com" in output.err
    assert "fingerprints" in output.err


@pytest.mark.asyncio
async def test_mcp_scan_saves_history_unless_disabled(tmp_path, monkeypatch):
    fastmcp = pytest.importorskip("fastmcp")
    from teardown.mcp_server import create_server
    monkeypatch.setattr("teardown.cli.HttpClient", OfflineClient)

    async with fastmcp.Client(create_server(data_dir=str(tmp_path))) as client:
        response = await client.call_tool("teardown_host", {"url": "example.com"})
        assert response.data["host"] == "example.com"
    with HistoryStore(tmp_path) as history:
        assert len(history.list_scans("example.com")) == 1

    async with fastmcp.Client(create_server(data_dir=str(tmp_path), history_enabled=False)) as client:
        await client.call_tool("scan_domain", {"domain": "example.com", "single": True})
    with HistoryStore(tmp_path) as history:
        assert len(history.list_scans("example.com")) == 1
