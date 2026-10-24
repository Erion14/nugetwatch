package nugetver

import "testing"

func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0.0", 0},
		{"1.0.0+build.1", "1.0.0+other", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.3.4", "1.2.3", 1},
		{"10.0.0", "9.99.99", 1},
		{"1.0.0-beta", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-BETA", "1.0.0-beta", 0},
		{"1.0.0-beta.2", "1.0.0-beta.10", -1}, // numeric labels compare numerically
		{"1.0.0-1", "1.0.0-alpha", -1},        // numeric before alphanumeric
		{"1.0.0-beta", "1.0.0-beta.1", -1},    // shorter prefix sorts first
		{"8.0.4", "8.0.4-rc.1", 1},
	}
	for _, tt := range tests {
		if got := mustParse(t, tt.a).Compare(mustParse(t, tt.b)); got != tt.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestParseRejectsMalformedVersions(t *testing.T) {
	for _, s := range []string{"", "1.", ".1", "1.2.3.4.5", "a.b", "1.0-", "1.0+", "1.0.0-be$ta", "1.0.0-beta..1", "-1.0", "1.0 .0"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", s)
		}
	}
}

func TestRangeContains(t *testing.T) {
	tests := []struct {
		rng string
		in  []string
		out []string
	}{
		{"[1.0, 2.0)", []string{"1.0", "1.0.0.0", "1.5", "2.0.0-beta"}, []string{"0.9.9", "2.0", "2.0.0.1"}},
		{"(1.0,2.0]", []string{"1.0.1", "2.0"}, []string{"1.0", "2.0.1"}},
		{"(, 5.8.4)", []string{"0.0.1", "5.8.3", "5.8.4-preview"}, []string{"5.8.4", "6.0"}},
		{"(,5.8.4]", []string{"5.8.4"}, []string{"5.8.5"}},
		{"[4.3.0, )", []string{"4.3.0", "99.0"}, []string{"4.2.9"}},
		{"(4.3.0,)", []string{"4.3.1"}, []string{"4.3.0"}},
		{"[1.2.3]", []string{"1.2.3", "1.2.3.0"}, []string{"1.2.4", "1.2.2"}},
		{"1.0", []string{"1.0", "3.0"}, []string{"0.9"}},
		{"  [8.0.0 , 8.0.4]  ", []string{"8.0.0", "8.0.4"}, []string{"8.0.5", "7.0.0"}},
		{"(, )", []string{"0.0.1", "100.0"}, nil},
		{"[1.0.0-beta, 1.0.0]", []string{"1.0.0-beta", "1.0.0-rc", "1.0.0"}, []string{"1.0.0-alpha"}},
	}
	for _, tt := range tests {
		r, err := ParseRange(tt.rng)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", tt.rng, err)
		}
		for _, v := range tt.in {
			if !r.Contains(mustParse(t, v)) {
				t.Errorf("%q should contain %s", tt.rng, v)
			}
		}
		for _, v := range tt.out {
			if r.Contains(mustParse(t, v)) {
				t.Errorf("%q should not contain %s", tt.rng, v)
			}
		}
	}
}

func TestParseRangeRejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		"[",
		"[1.0",
		"1.0]",
		"[1.0, 2.0",
		"{1.0, 2.0}",
		"(1.0)", // single version must be inclusive
		"[1.0)", // single version must be inclusive
		"[1.0, 2.0, 3.0]",
		"[2.0, 1.0]", // min > max
		"(1.0, 1.0]", // empty
		"[1.0, 1.0)", // empty
		"[abc, 2.0)",
		"[1.0, x)",
	} {
		if r, err := ParseRange(s); err == nil {
			t.Errorf("ParseRange(%q) = %+v, want error", s, r)
		}
	}
}
