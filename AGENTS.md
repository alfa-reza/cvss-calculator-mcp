# Agent Instructions — CVSS Calculator MCP

Read [`PRD.md`](PRD.md) before changing code. It defines the authoritative v1.0 scope and acceptance tests. Follow the existing repository layout if source already exists.

## Product boundaries

- **KISS:** one Go executable (`cvss-calculator-mcp`), one MCP tool (`calculate_cvss`), two required strings (`version`, `vector`).
- CVSS **2.0, 3.0, 3.1, 4.0**; **Strict Base Only**; success returns **one text number with one decimal**. Reject invalid inputs; never guess, rewrite, or silently fill metrics.
- Use the **official MCP Go SDK** and **`pandatix/go-cvss`**. Never reimplement CVSS scoring formulas.
- Default stdio; explicit `--transport stdio` or `--transport http`. HTTP is foreground, loopback `127.0.0.1:43871`, endpoint `/mcp`, configurable `--listen`.
- No Docker requirement, database, extra tools, daemon/background mode, new API, or unnecessary framework.

## Engineering workflow

1. Check version-matched **MCP SDK, Go, and FIRST CVSS** documentation before relying on an API or scoring assumption.
2. Make the smallest change satisfying the PRD; keep scoring/validation shared across transports.
3. Write table-driven tests for valid/invalid vectors; compare scores with **independent FIRST references**, not just the library under test. Test real stdio and HTTP MCP calls.
4. Run `gofmt`, `go vet ./...`, `go test ./...`, and (where supported) `go test -race ./...`. Build the binary. Report actual test results; never claim unrun checks passed.
5. Keep stdout clean in stdio mode; send diagnostics to stderr. Use errors visible to agents for bad vectors and fail closed.
6. Preserve Apache-2.0 licensing and FIRST attribution; do not imply official FIRST endorsement.

## Sources of truth

- Product contract and Definition of Done: [`PRD.md`](PRD.md)
- MCP SDK: https://github.com/modelcontextprotocol/go-sdk
- CVSS library: https://github.com/pandatix/go-cvss
- CVSS specifications: https://www.first.org/cvss/

If a decision changes public behavior or adds scope, flag it instead of inventing a feature. Stop and report blockers clearly.
