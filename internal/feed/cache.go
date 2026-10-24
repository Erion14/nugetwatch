package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxBody bounds a single feed document; the real base page is under 1 MB.
const maxBody = 64 << 20

// meta is stored next to each cached body.
type meta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
	FetchedAt    time.Time `json:"fetchedAt"` // last time the server confirmed this body
	MaxAge       int64     `json:"maxAgeSeconds"`
}

type outcome int

const (
	fromCache   outcome = iota // fresh per Cache-Control, no request made
	revalidated                // 304 Not Modified
	downloaded                 // 200 OK
	staleCache                 // request failed, older cached copy used
)

type result struct {
	outcome   outcome
	fetchedAt time.Time
	err       error // the network error behind a staleCache outcome
}

// fetcher is a tiny HTTP cache: it honours Cache-Control max-age, revalidates
// with If-None-Match / If-Modified-Since, and falls back to the cached copy
// when the network fails.
type fetcher struct {
	http      *http.Client
	dir       string
	userAgent string
	now       func() time.Time

	mu   sync.Mutex
	used map[string]bool
}

func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:16])
}

// get returns the document at url, passing its body to parse. A body that
// fails to parse is never written to the cache.
func (f *fetcher) get(ctx context.Context, url string, parse func([]byte) error) (result, error) {
	key := cacheKey(url)
	f.mu.Lock()
	f.used[key] = true
	f.mu.Unlock()

	m, body, cached := f.load(key)
	if cached && f.now().Sub(m.FetchedAt) < time.Duration(m.MaxAge)*time.Second {
		if parse(body) == nil {
			return result{outcome: fromCache, fetchedAt: m.FetchedAt}, nil
		}
		cached = false // corrupt cache entry: fetch unconditionally
	}

	oc, err := f.request(ctx, url, key, m, body, cached, parse)
	if err == nil {
		return result{outcome: oc, fetchedAt: f.now()}, nil
	}
	if cached && parse(body) == nil {
		return result{outcome: staleCache, fetchedAt: m.FetchedAt, err: err}, nil
	}
	return result{}, err
}

func (f *fetcher) request(ctx context.Context, url, key string, m meta, body []byte, cached bool, parse func([]byte) error) (outcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	if cached {
		if m.ETag != "" {
			req.Header.Set("If-None-Match", m.ETag)
		}
		if m.LastModified != "" {
			req.Header.Set("If-Modified-Since", m.LastModified)
		}
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && cached:
		if err := parse(body); err != nil {
			return 0, fmt.Errorf("cached copy of %s is corrupt: %w", url, err)
		}
		if et := resp.Header.Get("ETag"); et != "" {
			m.ETag = et
		}
		m.FetchedAt, m.MaxAge = f.now(), maxAge(resp.Header)
		return revalidated, f.saveMeta(key, m)
	case resp.StatusCode == http.StatusOK:
		newBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return 0, fmt.Errorf("reading %s: %w", url, err)
		}
		if err := parse(newBody); err != nil {
			return 0, fmt.Errorf("unexpected content at %s: %w", url, err)
		}
		if err := writeAtomic(filepath.Join(f.dir, key+".body"), newBody); err != nil {
			return 0, err
		}
		return downloaded, f.saveMeta(key, meta{
			URL:          url,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			FetchedAt:    f.now(),
			MaxAge:       maxAge(resp.Header),
		})
	default:
		return 0, fmt.Errorf("GET %s: unexpected status %s", url, resp.Status)
	}
}

func (f *fetcher) load(key string) (meta, []byte, bool) {
	var m meta
	raw, err := os.ReadFile(filepath.Join(f.dir, key+".json"))
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return meta{}, nil, false
	}
	body, err := os.ReadFile(filepath.Join(f.dir, key+".body"))
	if err != nil {
		return meta{}, nil, false
	}
	return m, body, true
}

func (f *fetcher) saveMeta(key string, m meta) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(f.dir, key+".json"), raw)
}

// prune removes cache entries not used during this run, e.g. superseded pages.
func (f *fetcher) prune() {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range entries {
		key, _, _ := strings.Cut(e.Name(), ".")
		if !f.used[key] {
			os.Remove(filepath.Join(f.dir, e.Name()))
		}
	}
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		os.Remove(tmp.Name())
	}
	return werr
}

// maxAge extracts Cache-Control max-age in seconds (0 when absent or no-cache).
func maxAge(h http.Header) int64 {
	var age int64
	for _, d := range strings.Split(h.Get("Cache-Control"), ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "no-cache" || d == "no-store" {
			return 0
		}
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				age = n
			}
		}
	}
	return age
}
