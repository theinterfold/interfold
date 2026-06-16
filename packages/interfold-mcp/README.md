# @interfold/mcp

MCP server for [The Interfold](https://theinterfold.com) documentation. Allows AI assistants to
answer questions about The Interfold by fetching content directly from
[docs.theinterfold.com](https://docs.theinterfold.com).

## Requirements

- Node.js **>=18.20.0** — required for ESM JSON import attributes, global `fetch`, and top-level
  await used by the `interfold-mcp` CLI.

## Tools

| Tool          | Description                                                                        |
| ------------- | ---------------------------------------------------------------------------------- |
| `list_docs`   | List all available documentation pages                                             |
| `read_doc`    | Read a specific page by slug (e.g. `introduction`, `ciphernode-operators/running`) |
| `search_docs` | Search for a keyword across all pages                                              |

## Integration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "interfold-docs": {
      "command": "npx",
      "args": ["-y", "@interfold/mcp"]
    }
  }
}
```

Restart Claude Desktop. The tools will be available automatically.

### VS Code (Continue)

Add a file `.continue/mcpServers/interfold.yaml` in your project:

```yaml
name: Interfold Docs
version: 0.1.0
schema: v1
mcpServers:
  - name: interfold-docs
    command: npx
    args:
      - -y
      - '@interfold/mcp'
```

### Cursor

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "interfold-docs": {
      "command": "npx",
      "args": ["-y", "@interfold/mcp"]
    }
  }
}
```

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "interfold-docs": {
      "command": "npx",
      "args": ["-y", "@interfold/mcp"]
    }
  }
}
```

## Usage

Once configured, ask your AI assistant questions like:

- _"What is an E3?"_
- _"How do I run a ciphernode?"_
- _"Explain the Interfold architecture"_
- _"Search the docs for threshold encryption"_

## License

LGPL-3.0-only
