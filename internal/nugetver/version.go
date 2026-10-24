// Package nugetver parses NuGet package versions and version ranges and
// compares them using NuGet's rules (SemVer 2.0 with an optional fourth
// numeric component, case-insensitive prerelease labels, build metadata ignored).
package nugetver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed NuGet version such as 1.2.3, 1.2.3.4 or 2.0.0-beta.1+sha.
type Version struct {
	nums [4]uint64
	pre  []string
	orig string
}

// Parse parses a NuGet version string. Missing numeric components are treated
// as zero, so "1.0" equals "1.0.0" and "1.0.0.0".
func Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	v := Version{orig: s}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		if i == len(core)-1 {
			return Version{}, fmt.Errorf("invalid version %q: empty build metadata", s)
		}
		core = core[:i]
	}
	var pre string
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core, pre = core[:i], core[i+1:]
		if pre == "" {
			return Version{}, fmt.Errorf("invalid version %q: empty prerelease", s)
		}
	}
	parts := strings.Split(core, ".")
	if core == "" || len(parts) > 4 {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q", s)
		}
		v.nums[i] = n
	}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
		for _, l := range v.pre {
			if l == "" || strings.IndexFunc(l, func(r rune) bool {
				return !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
			}) >= 0 {
				return Version{}, fmt.Errorf("invalid version %q: bad prerelease label", s)
			}
		}
	}
	return v, nil
}

// String returns the version as it was written.
func (v Version) String() string { return v.orig }

// Compare returns -1, 0 or +1 when v is less than, equal to or greater than w.
func (v Version) Compare(w Version) int {
	for i := range v.nums {
		if c := cmpUint(v.nums[i], w.nums[i]); c != 0 {
			return c
		}
	}
	// A release sorts after any of its prereleases.
	switch {
	case len(v.pre) == 0 && len(w.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(w.pre) == 0:
		return -1
	}
	for i := 0; i < len(v.pre) && i < len(w.pre); i++ {
		if c := cmpLabel(v.pre[i], w.pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(v.pre)), uint64(len(w.pre)))
}

func cmpLabel(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 64)
	bn, berr := strconv.ParseUint(b, 10, 64)
	switch {
	case aerr == nil && berr == nil:
		return cmpUint(an, bn)
	case aerr == nil:
		return -1 // numeric labels sort before alphanumeric ones
	case berr == nil:
		return 1
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
