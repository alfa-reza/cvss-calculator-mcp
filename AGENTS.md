# Agent Instructions — CVSS Calculator MCP

## Product boundaries

- **KISS:** one Go executable (`cvss-calculator-mcp`), one MCP tool (`calculate_cvss`), two required strings (`version`, `vector`).
- CVSS **2.0, 3.0, 3.1, 4.0**; **Strict Base Only**; success returns a JSON object containing `version`, the original `vector`, numeric `score`, and `severity`. Scores have one decimal place of precision. Reject invalid inputs; never guess, rewrite, or silently fill metrics.
- Use the **official MCP Go SDK** and **`pandatix/go-cvss`**. Never reimplement CVSS scoring formulas.
- Default stdio; explicit `--transport stdio` or `--transport http`. HTTP is foreground, loopback `127.0.0.1:43871`, endpoint `/mcp`, configurable `--listen`.
- No Docker requirement, database, extra tools, daemon/background mode, new API, or unnecessary framework.

## Engineering workflow

1. Check version-matched **MCP SDK, Go, and FIRST CVSS** documentation before relying on an API or scoring assumption.
2. Make the smallest change satisfying the documented product boundaries; keep scoring/validation shared across transports.
3. Write table-driven tests for valid/invalid vectors; compare scores with **independent FIRST references**, not just the library under test. Test real stdio and HTTP MCP calls.
4. Run `gofmt`, `go vet ./...`, `go test ./...`, and (where supported) `go test -race ./...`. Build the binary. Report actual test results; never claim unrun checks passed.
5. Keep stdout clean in stdio mode; send diagnostics to stderr. Use errors visible to agents for bad vectors and fail closed.

If a decision changes public behavior or adds scope, flag it instead of inventing a feature. Stop and report blockers clearly.
