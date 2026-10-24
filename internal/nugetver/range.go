package nugetver

import (
	"fmt"
	"strings"
)

// Range is a NuGet version range, e.g. "[1.0, 2.0)", "(, 5.8.4)", "[1.2.3]" or "1.0".
// A nil bound is unbounded.
type Range struct {
	Min, Max       *Version
	MinInc, MaxInc bool
	orig           string
}

// ParseRange parses NuGet version range syntax:
//
//	1.0         x >= 1.0
//	[1.0]       x == 1.0
//	(1.0,)      x > 1.0
//	(,1.0]      x <= 1.0
//	[1.0,2.0)   1.0 <= x < 2.0
//
// Whitespace around bounds is ignored. Empty ranges (min > max, or min == max
// without both ends inclusive) are rejected.
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	r := Range{orig: s}
	if s == "" {
		return Range{}, fmt.Errorf("empty version range")
	}
	open, close := s[0], s[len(s)-1]
	if open != '[' && open != '(' {
		v, err := Parse(s)
		if err != nil {
			return Range{}, fmt.Errorf("invalid version range %q: %w", s, err)
		}
		r.Min, r.MinInc = &v, true
		return r, nil
	}
	if len(s) < 2 || close != ']' && close != ')' {
		return Range{}, fmt.Errorf("invalid version range %q: unbalanced brackets", s)
	}
	r.MinInc, r.MaxInc = open == '[', close == ']'
	inner := s[1 : len(s)-1]

	lo, hi, hasComma := strings.Cut(inner, ",")
	if !hasComma {
		if !r.MinInc || !r.MaxInc {
			return Range{}, fmt.Errorf("invalid version range %q: single version must use [ ]", s)
		}
		v, err := Parse(inner)
		if err != nil {
			return Range{}, fmt.Errorf("invalid version range %q: %w", s, err)
		}
		r.Min, r.Max = &v, &v
		return r, nil
	}
	if strings.Contains(hi, ",") {
		return Range{}, fmt.Errorf("invalid version range %q: too many commas", s)
	}
	for _, b := range []struct {
		text string
		dst  **Version
	}{{lo, &r.Min}, {hi, &r.Max}} {
		t := strings.TrimSpace(b.text)
		if t == "" {
			continue
		}
		v, err := Parse(t)
		if err != nil {
			return Range{}, fmt.Errorf("invalid version range %q: %w", s, err)
		}
		*b.dst = &v
	}
	if r.Min != nil && r.Max != nil {
		c := r.Min.Compare(*r.Max)
		if c > 0 || c == 0 && !(r.MinInc && r.MaxInc) {
			return Range{}, fmt.Errorf("invalid version range %q: range is empty", s)
		}
	}
	return r, nil
}

// Contains reports whether v satisfies the range.
func (r Range) Contains(v Version) bool {
	if r.Min != nil {
		c := v.Compare(*r.Min)
		if c < 0 || c == 0 && !r.MinInc {
			return false
		}
	}
	if r.Max != nil {
		c := v.Compare(*r.Max)
		if c > 0 || c == 0 && !r.MaxInc {
			return false
		}
	}
	return true
}

// String returns the range as it was written.
func (r Range) String() string { return r.orig }
