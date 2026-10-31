package calculator

import (
	"fmt"
	"strings"
	"testing"
)

func TestCalculate(t *testing.T) {
	cases := []struct{ version, vector, want string }{
		{"2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C", "10.0"},
		{"3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"},
		{"3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"},
		{"3.1", "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", "9.8"},
		{"4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", "8.7"},
		{"3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0"},
		// FIRST CVSS 4.0 examples, CVE-2022-41741.
		{"3.1", "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.0"},
		{"4.0", "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "7.3"},
		// https://www.first.org/cvss/v2/guide, local antivirus example.
		{"2.0", "AV:L/AC:H/Au:N/C:C/I:C/A:C", "6.2"},
		// https://www.first.org/cvss/v3.0/examples, Cisco IOS example.
		{"3.0", "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "8.8"},
		// https://www.first.org/cvss/v4.0/examples, subsequent-system impact.
		{"3.1", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", "6.0"},
		{"4.0", "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", "5.9"},
	}
	for _, tc := range cases {
		t.Run(tc.version+"/"+tc.want+"/"+tc.vector, func(t *testing.T) {
			got, err := Calculate(tc.version, tc.vector)
			if err != nil || fmt.Sprintf("%.1f", got) != tc.want {
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestCalculateRejectsInvalid(t *testing.T) {
	v := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, tc := range []struct{ version, vector string }{
		{"5.0", v}, {"", v}, {"3.1", ""}, {"3.0", v}, {"2.0", "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"},
		{"3.1", strings.Replace(v, "/A:H", "", 1)}, {"3.1", v + "/AV:N"}, {"3.1", v + "/E:X"},
		{"3.1", strings.Replace(v, "AV:N", "av:N", 1)}, {"3.1", strings.Replace(v, "AV:N", "AV:X", 1)},
		{"3.1", v + "/"}, {"3.1", " " + v}, {"3.1", strings.Repeat("a", 1025)},
		{"2.0", "AC:L/AV:N/Au:N/C:C/I:C/A:C"},
		{"4.0", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
		{"4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:X"},
	} {
		t.Run(tc.version+tc.vector, func(t *testing.T) {
			if _, err := Calculate(tc.version, tc.vector); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
