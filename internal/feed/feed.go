// Package feed downloads, caches and queries NuGet's VulnerabilityInfo feed
// (https://learn.microsoft.com/nuget/api/vulnerability-info).
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Erion14/nugetwatch/internal/nugetver"
)

// DefaultServiceIndex is nuget.org's V3 service index.
const DefaultServiceIndex = "https://api.nuget.org/v3/index.json"

// Severity is an advisory severity as published by the feed.
type Severity int

const (
	Unknown  Severity = -1
	Low      Severity = 0
	Moderate Severity = 1
	High     Severity = 2
	Critical Severity = 3
)

var severityNames = map[Severity]string{Unknown: "Unknown", Low: "Low", Moderate: "Moderate", High: "High", Critical: "Critical"}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "Unknown"
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// AtLeast reports whether s meets threshold t. Unknown severity always
// qualifies, so unrated advisories are never silently ignored.
func (s Severity) AtLeast(t Severity) bool { return s == Unknown || s >= t }

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(name string) (Severity, error) {
	for s, n := range severityNames {
		if s != Unknown && strings.EqualFold(n, name) {
			return s, nil
		}
	}
	return Unknown, fmt.Errorf("unknown severity %q (want low, moderate, high or critical)", name)
}

// Advisory is one vulnerable version range of a package.
type Advisory struct {
	URL      string
	Severity Severity
	Range    nugetver.Range
}

// DB is the merged vulnerability data, keyed by lower-cased package ID.
type DB struct {
	advisories map[string][]Advisory

	Updated     time.Time // newest @updated among the data pages
	FetchedAt   time.Time // oldest time any document was confirmed by the server
	Stale       bool      // the feed could not be reached; cached data was used
	StaleReason string
	Requests    int // HTTP requests made while loading
	Downloaded  int // documents downloaded in full (HTTP 200)
	Skipped     int // advisories ignored because their range did not parse
}

// Match returns the advisories whose range contains the given package version.
// Package IDs are matched case-insensitively.
func (db *DB) Match(id string, v nugetver.Version) []Advisory {
	var out []Advisory
	for _, a := range db.advisories[strings.ToLower(id)] {
		if a.Range.Contains(v) {
			out = append(out, a)
		}
	}
	return out
}

// Client loads the vulnerability feed through an on-disk cache.
type Client struct {
	ServiceIndex string
	CacheDir     string
	HTTP         *http.Client
	UserAgent    string
	Now          func() time.Time // defaults to time.Now
}

type rawAdvisory struct {
	URL      string `json:"url"`
	Severity *int   `json:"severity"`
	Versions string `json:"versions"`
}

// Load resolves the VulnerabilityInfo resource from the service index and
// returns the merged data of all pages it lists. If the network is
// unavailable but every document is cached, the cached data is returned with
// Stale set; otherwise the error is returned.
func (c *Client) Load(ctx context.Context) (*DB, error) {
	f := &fetcher{http: c.HTTP, dir: c.CacheDir, userAgent: c.UserAgent, now: c.Now, used: map[string]bool{}}
	if f.http == nil {
		f.http = &http.Client{Timeout: 60 * time.Second}
	}
	if f.now == nil {
		f.now = time.Now
	}
	db := &DB{advisories: map[string][]Advisory{}}
	var mu sync.Mutex
	record := func(r result) {
		mu.Lock()
		defer mu.Unlock()
		if r.outcome != fromCache {
			db.Requests++
		}
		if r.outcome == downloaded {
			db.Downloaded++
		}
		if r.outcome == staleCache && !db.Stale {
			db.Stale, db.StaleReason = true, r.err.Error()
		}
		if db.FetchedAt.IsZero() || r.fetchedAt.Before(db.FetchedAt) {
			db.FetchedAt = r.fetchedAt
		}
	}

	var vulnIndexURL string
	r, err := f.get(ctx, c.ServiceIndex, func(b []byte) error {
		var idx struct {
			Resources []struct {
				ID   string `json:"@id"`
				Type string `json:"@type"`
			} `json:"resources"`
		}
		if err := json.Unmarshal(b, &idx); err != nil {
			return err
		}
		for _, res := range idx.Resources {
			if res.Type == "VulnerabilityInfo" || strings.HasPrefix(res.Type, "VulnerabilityInfo/") {
				vulnIndexURL = res.ID
				return nil
			}
		}
		return errors.New("service index has no VulnerabilityInfo resource")
	})
	if err != nil {
		return nil, fmt.Errorf("loading service index: %w", err)
	}
	record(r)

	type page struct {
		Name    string    `json:"@name"`
		ID      string    `json:"@id"`
		Updated time.Time `json:"@updated"`
	}
	var pages []page
	r, err = f.get(ctx, vulnIndexURL, func(b []byte) error {
		pages = nil
		if err := json.Unmarshal(b, &pages); err != nil {
			return err
		}
		if len(pages) == 0 {
			return errors.New("vulnerability index lists no pages")
		}
		for _, p := range pages {
			if p.ID == "" {
				return errors.New("vulnerability index entry without @id")
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("loading vulnerability index: %w", err)
	}
	record(r)

	data := make([]map[string][]rawAdvisory, len(pages))
	errs := make([]error, len(pages))
	var wg sync.WaitGroup
	for i, p := range pages {
		wg.Go(func() {
			r, err := f.get(ctx, p.ID, func(b []byte) error {
				data[i] = nil
				return json.Unmarshal(b, &data[i])
			})
			if err != nil {
				errs[i] = fmt.Errorf("loading vulnerability page %q: %w", p.Name, err)
				return
			}
			record(r)
		})
		if p.Updated.After(db.Updated) {
			db.Updated = p.Updated
		}
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	// Pages are additive: "update" holds advisories published since "base".
	type dedupKey struct{ url, versions string }
	seen := map[string]map[dedupKey]bool{}
	for _, d := range data {
		for id, advs := range d {
			lid := strings.ToLower(id)
			if seen[lid] == nil {
				seen[lid] = map[dedupKey]bool{}
			}
			for _, a := range advs {
				k := dedupKey{a.URL, a.Versions}
				if seen[lid][k] {
					continue
				}
				seen[lid][k] = true
				rng, err := nugetver.ParseRange(a.Versions)
				if err != nil {
					db.Skipped++
					continue
				}
				sev := Unknown
				if a.Severity != nil {
					if s := Severity(*a.Severity); s >= Low && s <= Critical {
						sev = s
					}
				}
				db.advisories[lid] = append(db.advisories[lid], Advisory{URL: a.URL, Severity: sev, Range: rng})
			}
		}
	}

	if !db.Stale {
		f.prune()
	}
	return db, nil
}
