# MCP server

Teardown exposes its scan contract as MCP tools. The server runs over **stdio**
by default, which lets an MCP client launch it on demand. It can also serve
**Streamable HTTP** on loopback for a client that connects to a URL.

## Run it with `uvx`

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and make
sure `uvx` is on the `PATH` seen by your MCP client. Then run:

```bash
uvx --from 'tech-teardown[mcp]' teardown-mcp
```

`tech-teardown` is the distribution name, while `teardown-mcp` is its MCP
executable. The `[mcp]` extra installs FastMCP. `uvx` creates an isolated tool
environment; there is no need to install the package into your project. In
JSON config files, pass `tech-teardown[mcp]` as one argument without shell
quotes. For repeatable deployments, pin a version, for example
`tech-teardown[mcp]==0.6.0`, and update it deliberately.

If you have already installed the extra with `pip install
'tech-teardown[mcp]'`, run `teardown-mcp` directly. A local checkout can use
`.venv/bin/teardown-mcp` after `pip install -e '.[mcp]'`.

## Add it to an MCP client

### Codex CLI and IDE

```bash
codex mcp add teardown -- uvx --from 'tech-teardown[mcp]' teardown-mcp
codex mcp list
```

Codex stores this in its MCP configuration and shares it between the CLI and
IDE extension. See the [Codex MCP guide](https://developers.openai.com/codex/mcp).

### Claude Code

```bash
claude mcp add --scope user --transport stdio teardown -- uvx --from 'tech-teardown[mcp]' teardown-mcp
claude mcp list
```

`--scope user` makes it available across projects. Use `--scope project` to
share it through a project `.mcp.json`, or omit the scope for a local project
entry. Check `/mcp` inside Claude Code after starting a session. See the
[Claude Code MCP guide](https://code.claude.com/docs/en/mcp).

### Cursor

Put this in `~/.cursor/mcp.json` for all projects, or `.cursor/mcp.json` for
one project:

```json
{
  "mcpServers": {
    "teardown": {
      "command": "uvx",
      "args": ["--from", "tech-teardown[mcp]", "teardown-mcp"]
    }
  }
}
```

Restart Cursor or refresh MCP servers, then check that Teardown's tools appear
in the Agent tool list. See [Cursor's MCP guide](https://docs.cursor.com/context/model-context-protocol).

### VS Code with GitHub Copilot

For the current Copilot harness, add a server through **Chat: Open
Customizations → MCP Servers → Add Server**, or put this in
`~/.copilot/mcp-config.json` for personal use. A workspace-root `.mcp.json`
uses the same portable format when workspace MCP configuration is enabled:

```json
{
  "mcpServers": {
    "teardown": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "tech-teardown[mcp]", "teardown-mcp"],
      "tools": ["*"]
    }
  }
}
```

Use the Copilot harness's `mcpServers` format for new configurations; older
`.vscode/mcp.json` files use a different `servers` format. See the
[VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

### Gemini CLI

Put this in `~/.gemini/settings.json` for user scope or `.gemini/settings.json`
for one project:

```json
{
  "mcpServers": {
    "teardown": {
      "command": "uvx",
      "args": ["--from", "tech-teardown[mcp]", "teardown-mcp"]
    }
  }
}
```

Run `gemini mcp list`, then `/mcp` in a trusted Gemini CLI workspace. See
the [Gemini CLI MCP guide](https://geminicli.com/docs/tools/mcp-server/).

### Claude Desktop

Use the same `mcpServers` JSON shape as the Cursor example in Claude Desktop's
local `claude_desktop_config.json`. On macOS, the file is at
`~/Library/Application Support/Claude/claude_desktop_config.json`; on Windows,
it is at `%APPDATA%\Claude\claude_desktop_config.json`. Fully quit and restart
the app, then check the Connectors menu for Teardown's tools. Local desktop
servers use your own machine; a cloud remote connector is a different setup. See
[Claude Desktop's local MCP guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop).

The repository's [`.mcp.json.example`](../.mcp.json.example) is a compact
stdio starting point. If the client cannot find `uvx`, replace `"uvx"` with
its absolute executable path. Launching from a GUI often uses a different
`PATH` than your terminal.

## Tools and data handling

| Tool | Result |
| --- | --- |
| `teardown_host(url)` | One `HostTeardown` record |
| `teardown_domain(domain, max_hosts, max_probes, active_dns, use_subfinder)` | Full `ScanResult`; active DNS is opt-in |
| `enumerate_subdomains(domain, use_subfinder)` | In-scope passive host list without liveness probes |
| `scan_domain(domain, single, max_hosts, max_probes)` | Compatibility scan entry point |
| `diff_scans(old, new)` | Normalized comparison of two scan JSON objects |

For example, ask your client to call `teardown_host` for `example.com`, then
inspect the returned `detections`, `network`, and `opsec_findings` fields. A
domain scan can take longer than a host scan; its host and probe caps are tool
arguments. Clients may need a longer MCP tool timeout for larger domains.

MCP scans use the same bounded collection path as the CLI and save SQLite
history and sanitized first-party artifacts by default. Add server startup
flags after `teardown-mcp` to change this behavior:

```bash
uvx --from 'tech-teardown[mcp]' teardown-mcp --no-history --no-artifacts
uvx --from 'tech-teardown[mcp]' teardown-mcp --data-dir /path/to/private-data
```

## Streamable HTTP

Start a local server:

```bash
uvx --from 'tech-teardown[mcp]' teardown-mcp --transport http --host 127.0.0.1 --port 8000
```

Connect an HTTP-capable client to `http://127.0.0.1:8000/mcp`. Keep the process
running while the client uses it. Loopback is the default bind address. Do not
expose this unauthenticated endpoint to a network; if you need remote access,
put appropriate authentication and transport security in front of it.

## Troubleshooting

- If the MCP process exits at startup, run the exact `uvx` command in a
  terminal and check `uvx` is on the client's `PATH`.
- If no tools appear, verify the client selected **stdio** for the command or
  **Streamable HTTP** for the `/mcp` URL. Restart or refresh its MCP list.
- If a scan seems slow, start with `teardown_host` or lower `max_probes` and
  `max_hosts` for `teardown_domain`.
- If you need to avoid local scan storage, add `--no-history --no-artifacts`
  to the server command. The response cache is still used by the scan path.
