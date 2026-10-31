package mcpserver

import (
	"context"
	"encoding/json"

	"github.com/alfa-reza/cvss-calculator-mcp/internal/calculator"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type calculateInput struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
}

type calculateOutput struct {
	Version  string  `json:"version"`
	Vector   string  `json:"vector"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

func severity(version string, score float64) string {
	if version == "2.0" {
		if score < 4 {
			return "Low"
		}
		if score < 7 {
			return "Medium"
		}
		return "High"
	}
	if score == 0 {
		return "None"
	}
	if score < 4 {
		return "Low"
	}
	if score < 7 {
		return "Medium"
	}
	if score < 9 {
		return "High"
	}
	return "Critical"
}

func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "cvss-calculator-mcp", Version: "1.0.0"}, nil)
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"version": map[string]any{"type": "string", "enum": []string{"2.0", "3.0", "3.1", "4.0"}, "description": "CVSS version"},
			"vector":  map[string]any{"type": "string", "minLength": 1, "description": "Complete case-sensitive Base-only vector. v2: AV L/A/N, AC H/M/L, Au M/S/N, C/I/A N/P/C. v3: AV N/A/L/P, AC L/H, PR N/L/H, UI N/R, S U/C, C/I/A H/L/N. v4: AV N/A/L/P, AC L/H, AT N/P, PR N/L/H, UI N/P/A, VC/VI/VA/SC/SI/SA H/L/N."},
		},
		"required": []string{"version", "vector"}, "additionalProperties": false,
	}
	mcp.AddTool(server, &mcp.Tool{Name: "calculate_cvss", Description: "Calculate a CVSS Base-only score for 2.0, 3.0, 3.1 or 4.0. Supply every metric; never guess. v2: AV Access Vector, AC Access Complexity, Au Authentication, C/I/A Confidentiality/Integrity/Availability. v3: AV Attack Vector, AC Attack Complexity, PR Privileges Required, UI User Interaction, S Scope, C/I/A impact. v4: AT Attack Requirements, VC/VI/VA Vulnerable System impact, SC/SI/SA Subsequent System impact. Rejects non-Base metrics.", InputSchema: schema},
		func(_ context.Context, _ *mcp.CallToolRequest, input calculateInput) (*mcp.CallToolResult, any, error) {
			score, err := calculator.Calculate(input.Version, input.Vector)
			if err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil, nil
			}
			output := calculateOutput{input.Version, input.Vector, score, severity(input.Version, score)}
			data, err := json.Marshal(output)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
		})
	return server
}
