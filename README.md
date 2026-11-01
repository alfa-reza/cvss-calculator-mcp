<h1 align="center">CVSS Calculator MCP</h1>

<p align="center">A lightweight CVSS Base Score calculator for AI agents, built with Go.</p>

<p align="center">
  <a href="https://github.com/alfa-reza/cvss-calculator-mcp/releases"><img src="https://img.shields.io/badge/version-v1.0.0-2563eb?style=flat-square" alt="Version 1.0.0" height="20"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/alfa-reza/cvss-calculator-mcp?style=flat-square&logo=go&label=Go" alt="Go version" height="20"></a>
  <a href="https://github.com/alfa-reza/cvss-calculator-mcp/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/alfa-reza/cvss-calculator-mcp/ci.yml?branch=main&label=CI&style=flat-square" alt="CI status" height="20"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/alfa-reza/cvss-calculator-mcp?style=flat-square" alt="License" height="20"></a>
</p>

<p align="center">
  <a href="https://cvss.my.id">Website</a> 
</p>

Calculate and validate **CVSS 2.0, 3.0, 3.1, and 4.0** Base Scores through a single MCP tool: `calculate_cvss`. Supports local **stdio** and remote **Streamable HTTP**.

## Quick Start

### Option 1 — Install Locally

**Linux / macOS:**

```bash
curl -fsSL https://get.cvss.my.id/install.sh | bash
```

Add the installed binary to your MCP client (choose one):

```bash
# Claude Code
claude mcp add --scope user cvss-calculator -- cvss-calculator-mcp

# Codex
codex mcp add cvss-calculator -- cvss-calculator-mcp

# OpenCode v2
opencode mcp add cvss-calculator --global -- cvss-calculator-mcp
```

Also available via [GitHub Releases](https://github.com/alfa-reza/cvss-calculator-mcp/releases) (including Windows) or `go install github.com/alfa-reza/cvss-calculator-mcp/cmd/cvss-calculator-mcp@latest` (Go 1.25+). Ensure the binary is in your `PATH`.

### Option 2 — Free Remote MCP

No installation or API key required. Connect to `https://cvss.my.id/mcp`:

```bash
# Claude Code
claude mcp add --scope user --transport http cvss-calculator https://cvss.my.id/mcp

# Codex
codex mcp add cvss-calculator --url https://cvss.my.id/mcp

# OpenCode v2
opencode mcp add cvss-calculator --global --url https://cvss.my.id/mcp
```

**Rate limit:** 5 requests per minute per IP address. Use the local option to avoid this shared-service limit.

<details>
<summary><strong>Other MCP clients (Cursor, Claude Desktop, VS Code, etc.)</strong></summary>

Use `cvss-calculator-mcp` as a **local stdio command**, or `https://cvss.my.id/mcp` as a **remote Streamable HTTP endpoint**. Configuration formats depend on the client.

**Cursor / Claude Desktop** — local configuration (`mcpServers`):

```json
{
  "mcpServers": {
    "cvss-calculator": { "command": "cvss-calculator-mcp" }
  }
}
```

For **Cursor remote**, use `"url": "https://cvss.my.id/mcp"` instead of the `command` entry.

**VS Code** — remote configuration (`.vscode/mcp.json`):

```json
{
  "servers": {
    "cvss-calculator": { "type": "http", "url": "https://cvss.my.id/mcp" }
  }
}
```

See the client documentation for configuration locations and setup: [Cursor](https://cursor.com/docs/mcp) · [Claude Desktop](https://modelcontextprotocol.io/docs/develop/connect-local-servers) · [VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers).

</details>

## Usage

Ask your connected AI assistant:

> Calculate the CVSS 3.1 Base Score for `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

The `calculate_cvss` tool accepts `version` and `vector`, returning a score and severity (for this example, **9.8 — Critical**). Only complete **Base** vectors are supported; no CVE lookups or vulnerability scanning.

## Self-Hosting

The Go binary uses **stdio** by default. For Streamable HTTP, run `cvss-calculator-mcp --transport http` (listens on `127.0.0.1:43871/mcp` by default; customize with `--listen`).

## License

[Apache-2.0](LICENSE). CVSS is maintained by [FIRST](https://www.first.org/cvss/); this project is independent of FIRST.
