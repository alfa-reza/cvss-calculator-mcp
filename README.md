# CVSS Calculator MCP

A small, offline Model Context Protocol server that calculates **Base-only**
CVSS 2.0, 3.0, 3.1, and 4.0 scores. It exposes one tool, `calculate_cvss`.
The caller selects the metrics; the server validates and scores them. It does
not assess vulnerabilities, look up CVEs, or calculate Threat, Temporal,
Environmental, or Supplemental metrics.

## Requirements and installation

Go 1.25 or newer is required to build from source. Download the appropriate
release archive when available, or build locally:

```sh
go install github.com/alfa-reza/cvss-calculator-mcp/cmd/cvss-calculator-mcp@latest
# Alternatively, from a source checkout:
go build -trimpath -o cvss-calculator-mcp ./cmd/cvss-calculator-mcp
```

## Usage

Run the executable with no arguments for MCP over stdio. A generic MCP client
configuration, using the absolute path to your executable, is:

```json
{
  "mcpServers": {
    "cvss-calculator": {
      "command": "/absolute/path/to/cvss-calculator-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

For Streamable HTTP, run in the foreground:

```sh
cvss-calculator-mcp --transport http
cvss-calculator-mcp --transport http --listen 127.0.0.1:9000
```

The default endpoint is `http://127.0.0.1:43871/mcp`. Stop it with Ctrl+C.
Use `--help` for flags and `--version` for the application version.

Call `calculate_cvss` with exactly two strings:

```json
{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
```

The text result is a JSON object:

```json
{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8,"severity":"Critical"}
```

Another example:

```json
{"version":"4.0","vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
```

This returns a JSON object containing `version`, the original `vector`, the numeric
`score` (8.7 for this example), and `severity`. Scores follow the [FIRST CVSS 4.0 FAQ](https://www.first.org/cvss/faq).
CVSS 3.x and 4.0 use FIRST's qualitative severity scale; CVSS 2.0 uses the
[NVD severity ratings](https://nvd.nist.gov/vuln-metrics/cvss): Low (0.0–3.9),
Medium (4.0–6.9), and High (7.0–10.0).
The version must match the vector header; CVSS 2.0 has no header. Every Base
metric is mandatory. v2 and v4 require specification order; v3 metrics may
appear in any order. Invalid, duplicate, missing, non-Base, incorrectly cased,
or oversized metrics are rejected; nothing is guessed or silently repaired.
Errors are visible as MCP errors and do not return a score.

## HTTP deployment

HTTP binds only to loopback by default. Browser requests with an Origin must
match the request Host; local requests are protected against DNS rebinding.
For public access, use an external HTTPS reverse proxy and configure its Host
header to the local upstream address. TLS, access control, rate limiting,
allowed origins, and other operational protections are the operator's
responsibility. Do not expose the service publicly without those protections.

## Development

```sh
go mod tidy
gofmt -w .
go vet ./...
go test ./...
CVSS_TEST_RACE=1 go test -race ./...
go build -trimpath -o cvss-calculator-mcp ./cmd/cvss-calculator-mcp
```

The service uses the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
and [pandatix/go-cvss](https://github.com/pandatix/go-cvss). For metric
definitions and guidance, consult FIRST's [CVSS specifications](https://www.first.org/cvss/).
CVSS is owned by FIRST.Org, Inc. and used by permission; this project is not
endorsed by FIRST. When publishing scores, retain and publish the input vector
alongside the score as required by FIRST's usage conditions.

Licensed under [Apache-2.0](LICENSE). Dependency license texts are included in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
