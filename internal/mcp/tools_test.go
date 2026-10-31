package mcpserver

import "testing"

func TestSeverity(t *testing.T) {
	for _, tc := range []struct {
		version string
		score   float64
		want    string
	}{
		{"2.0", 0, "Low"}, {"2.0", 3.9, "Low"}, {"2.0", 4, "Medium"},
		{"2.0", 6.9, "Medium"}, {"2.0", 7, "High"}, {"2.0", 10, "High"},
		{"3.0", 0, "None"}, {"3.1", 0.1, "Low"}, {"3.1", 3.9, "Low"},
		{"3.1", 4, "Medium"}, {"3.1", 6.9, "Medium"}, {"3.1", 7, "High"},
		{"4.0", 8.9, "High"}, {"4.0", 9, "Critical"}, {"4.0", 10, "Critical"},
	} {
		if got := severity(tc.version, tc.score); got != tc.want {
			t.Errorf("severity(%q, %v) = %q, want %q", tc.version, tc.score, got, tc.want)
		}
	}
}
