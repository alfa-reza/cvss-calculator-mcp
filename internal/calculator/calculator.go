package calculator

import (
	"fmt"
	"math"
	"strings"

	v20 "github.com/pandatix/go-cvss/20"
	v30 "github.com/pandatix/go-cvss/30"
	v31 "github.com/pandatix/go-cvss/31"
	v40 "github.com/pandatix/go-cvss/40"
)

// Calculate validates a complete Base vector before delegating scoring.
func Calculate(version, vector string) (float64, error) {
	var order []string
	var allowed map[string]string
	switch version {
	case "2.0":
		order = []string{"AV", "AC", "Au", "C", "I", "A"}
		allowed = map[string]string{"AV": "LAN", "AC": "HML", "Au": "MSN", "C": "NPC", "I": "NPC", "A": "NPC"}
	case "3.0", "3.1":
		order = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
		allowed = map[string]string{"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"}
	case "4.0":
		order = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
		allowed = map[string]string{"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN"}
	default:
		return 0, fmt.Errorf("Unsupported version: choose 2.0, 3.0, 3.1, or 4.0")
	}
	if len(vector) == 0 || len(vector) > 1024 {
		return 0, fmt.Errorf("Vector must contain 1 to 1024 bytes")
	}
	if version != "2.0" {
		header, rest, ok := strings.Cut(vector, "/")
		if !ok || header != "CVSS:"+version {
			return 0, fmt.Errorf("Version mismatch or invalid header: expected CVSS:%s", version)
		}
		vector = rest
	}
	tokens := strings.Split(vector, "/")
	seen := make(map[string]string, len(order))
	for i, token := range tokens {
		name, value, ok := strings.Cut(token, ":")
		if !ok || name == "" || value == "" || strings.Contains(value, ":") {
			return 0, fmt.Errorf("Malformed vector metric")
		}
		values, ok := allowed[name]
		if !ok {
			return 0, fmt.Errorf("Unknown or non-Base metric")
		}
		if _, exists := seen[name]; exists {
			return 0, fmt.Errorf("Duplicate metric: %s", name)
		}
		if len(value) != 1 || !strings.Contains(values, value) {
			return 0, fmt.Errorf("Invalid value for metric %s", name)
		}
		if (version == "2.0" || version == "4.0") && (i >= len(order) || name != order[i]) {
			return 0, fmt.Errorf("Invalid metric order at %s", name)
		}
		seen[name] = value
	}
	for _, name := range order {
		if _, ok := seen[name]; !ok {
			return 0, fmt.Errorf("Missing Base metric: %s", name)
		}
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+":"+seen[name])
	}
	canonical := strings.Join(parts, "/")
	if version != "2.0" {
		canonical = "CVSS:" + version + "/" + canonical
	}
	var score float64
	switch version {
	case "2.0":
		v, e := v20.ParseVector(canonical)
		if e != nil {
			return 0, fmt.Errorf("Invalid vector: %w", e)
		}
		score = v.BaseScore()
	case "3.0":
		v, e := v30.ParseVector(canonical)
		if e != nil {
			return 0, fmt.Errorf("Invalid vector: %w", e)
		}
		score = v.BaseScore()
	case "3.1":
		v, e := v31.ParseVector(canonical)
		if e != nil {
			return 0, fmt.Errorf("Invalid vector: %w", e)
		}
		score = v.BaseScore()
	case "4.0":
		v, e := v40.ParseVector(canonical)
		if e != nil {
			return 0, fmt.Errorf("Invalid vector: %w", e)
		}
		score = v.Score()
	}
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 10 {
		return 0, fmt.Errorf("Calculation produced an invalid score")
	}
	return score, nil
}
