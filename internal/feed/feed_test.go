package feed

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Erion14/nugetwatch/internal/nugetver"
)

// fakeFeed mimics nuget.org: documents with ETags and Cache-Control max-age.
type fakeFeed struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	docs        map[string]string // path -> body
	down        bool
	hits        map[string]int
	conditional int // requests carrying a matching If-None-Match
}

func newFakeFeed(t *testing.T) *fakeFeed {
	ff := &fakeFeed{t: t, hits: map[string]int{}}
	ff.srv = httptest.NewServer(http.HandlerFunc(ff.serve))
	t.Cleanup(ff.srv.Close)
	ff.docs = map[string]string{
		"/v3/index.json": `{"version":"3.0.0","resources":[
			{"@id":"` + ff.srv.URL + `/v3/registration5-gz-semver2/","@type":"RegistrationsBaseUrl/3.6.0"},
			{"@id":"` + ff.srv.URL + `/v3/vulnerabilities/index.json","@type":"VulnerabilityInfo/6.7.0"}]}`,
		"/base.json": `{
			"newtonsoft.json": [{"url":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr","severity":2,"versions":"(, 13.0.1)"}],
			"system.text.json": [
				{"url":"https://example.test/a","severity":3,"versions":"[8.0.0, 8.0.4]"},
				{"url":"https://example.test/bad","severity":1,"versions":"[9.0, 1.0]"},
				{"url":"https://example.test/unrated","versions":"[6.0.0, 6.0.1)"}]
		}`,
		"/update1.json": `{"newtonsoft.json": [{"url":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr","severity":2,"versions":"(, 13.0.1)"}]}`,
	}
	ff.setIndex("/update1.json")
	return ff
}

func (ff *fakeFeed) setIndex(updatePath string) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	ff.docs["/v3/vulnerabilities/index.json"] = fmt.Sprintf(`[
		{"@name":"base","@id":"%s/base.json","@updated":"2026-10-19T23:33:13.4608684Z"},
		{"@name":"update","@id":"%s%s","@updated":"2026-10-24T11:33:49.6656901Z"}]`, ff.srv.URL, ff.srv.URL, updatePath)
}

func (ff *fakeFeed) serve(w http.ResponseWriter, r *http.Request) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	ff.hits[r.URL.Path]++
	if ff.down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	body, ok := ff.docs[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(body)))
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "max-age=3600, must-revalidate")
	if r.Header.Get("If-None-Match") == etag {
		ff.conditional++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	fmt.Fprint(w, body)
}

func (ff *fakeFeed) totalHits() int {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	n := 0
	for _, h := range ff.hits {
		n += h
	}
	return n
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClient(ff *fakeFeed, dir string, c *clock) *Client {
	return &Client{ServiceIndex: ff.srv.URL + "/v3/index.json", CacheDir: dir, HTTP: ff.srv.Client(), UserAgent: "test", Now: c.now}
}

func mustLoad(t *testing.T, c *Client) *DB {
	t.Helper()
	db, err := c.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return db
}

func v(t *testing.T, s string) nugetver.Version {
	t.Helper()
	ver, err := nugetver.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return ver
}

func TestLoadMergesPagesAndMatches(t *testing.T) {
	ff := newFakeFeed(t)
	db := mustLoad(t, newClient(ff, t.TempDir(), &clock{time.Now()}))

	if got := db.Match("Newtonsoft.JSON", v(t, "12.0.1")); len(got) != 1 {
		t.Errorf("Newtonsoft.Json 12.0.1: got %d advisories, want 1 (deduplicated across pages)", len(got))
	} else if got[0].Severity != High || got[0].Range.String() != "(, 13.0.1)" {
		t.Errorf("advisory = %+v", got[0])
	}
	if got := db.Match("newtonsoft.json", v(t, "13.0.1")); len(got) != 0 {
		t.Errorf("13.0.1 is outside (, 13.0.1) but matched %+v", got)
	}
	if got := db.Match("System.Text.Json", v(t, "8.0.4")); len(got) != 1 || got[0].Severity != Critical {
		t.Errorf("System.Text.Json 8.0.4 = %+v, want one Critical", got)
	}
	if got := db.Match("System.Text.Json", v(t, "6.0.0")); len(got) != 1 || got[0].Severity != Unknown {
		t.Errorf("unrated advisory = %+v, want Unknown severity", got)
	}
	if db.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 malformed range", db.Skipped)
	}
	if want := time.Date(2026, 10, 24, 11, 33, 49, 665690100, time.UTC); !db.Updated.Equal(want) {
		t.Errorf("Updated = %v, want %v", db.Updated, want)
	}
}

func TestCacheFreshnessAndRevalidation(t *testing.T) {
	ff := newFakeFeed(t)
	dir := t.TempDir()
	clk := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := newClient(ff, dir, clk)

	db := mustLoad(t, c)
	if db.Requests != 4 || db.Downloaded != 4 || db.Stale {
		t.Fatalf("cold load: requests=%d downloaded=%d stale=%v, want 4/4/false", db.Requests, db.Downloaded, db.Stale)
	}

	// Within max-age: no network at all.
	clk.t = clk.t.Add(30 * time.Minute)
	db = mustLoad(t, c)
	if db.Requests != 0 || ff.totalHits() != 4 {
		t.Errorf("warm load made %d requests (server saw %d total), want 0 new", db.Requests, ff.totalHits())
	}
	if len(db.Match("newtonsoft.json", v(t, "12.0.1"))) != 1 {
		t.Error("cached data lost advisories")
	}

	// Past max-age: conditional requests, all answered with 304.
	clk.t = clk.t.Add(2 * time.Hour)
	db = mustLoad(t, c)
	if db.Requests != 4 || db.Downloaded != 0 || ff.conditional != 4 {
		t.Errorf("revalidation: requests=%d downloaded=%d 304s=%d, want 4/0/4", db.Requests, db.Downloaded, ff.conditional)
	}
	if !db.FetchedAt.Equal(clk.t) {
		t.Errorf("FetchedAt = %v, want refreshed to %v", db.FetchedAt, clk.t)
	}

	// The feed publishes a new update page: only changed documents are
	// downloaded and the superseded page is evicted from the cache.
	ff.mu.Lock()
	ff.docs["/update2.json"] = `{"serilog": [{"url":"https://example.test/s","severity":0,"versions":"[1.0, 2.0)"}]}`
	ff.mu.Unlock()
	ff.setIndex("/update2.json")
	clk.t = clk.t.Add(2 * time.Hour)
	db = mustLoad(t, c)
	if db.Downloaded != 2 { // vulnerability index + update2
		t.Errorf("after feed update downloaded=%d, want 2", db.Downloaded)
	}
	if len(db.Match("Serilog", v(t, "1.5"))) != 1 {
		t.Error("new advisory from update page not found")
	}
	if _, err := os.Stat(dir + "/" + cacheKey(ff.srv.URL+"/update1.json") + ".body"); !os.IsNotExist(err) {
		t.Errorf("superseded page still cached (stat err = %v)", err)
	}
}

func TestUnreachableFeedUsesStaleCache(t *testing.T) {
	ff := newFakeFeed(t)
	clk := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := newClient(ff, t.TempDir(), clk)
	first := mustLoad(t, c)

	ff.mu.Lock()
	ff.down = true
	ff.mu.Unlock()
	clk.t = clk.t.Add(48 * time.Hour)
	db := mustLoad(t, c)
	if !db.Stale || !strings.Contains(db.StaleReason, "503") {
		t.Errorf("Stale=%v reason=%q, want stale with HTTP 503 reason", db.Stale, db.StaleReason)
	}
	if !db.FetchedAt.Equal(first.FetchedAt) {
		t.Errorf("FetchedAt = %v, want age of cached data %v", db.FetchedAt, first.FetchedAt)
	}
	if len(db.Match("newtonsoft.json", v(t, "12.0.1"))) != 1 {
		t.Error("stale cache did not provide advisories")
	}
}

func TestUnreachableFeedWithoutCacheFails(t *testing.T) {
	ff := newFakeFeed(t)
	ff.down = true
	if _, err := newClient(ff, t.TempDir(), &clock{time.Now()}).Load(context.Background()); err == nil {
		t.Fatal("Load succeeded with feed down and empty cache")
	}
}

func TestInvalidResponseDoesNotReplaceCache(t *testing.T) {
	ff := newFakeFeed(t)
	clk := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := newClient(ff, t.TempDir(), clk)
	mustLoad(t, c)

	ff.mu.Lock()
	ff.docs["/base.json"] = `<html>maintenance</html>`
	ff.mu.Unlock()
	clk.t = clk.t.Add(48 * time.Hour)
	db := mustLoad(t, c)
	if !db.Stale {
		t.Error("garbage response should be reported as stale data")
	}
	if len(db.Match("newtonsoft.json", v(t, "12.0.1"))) != 1 {
		t.Error("cached base page was replaced by garbage")
	}
}

func TestMissingVulnerabilityResource(t *testing.T) {
	ff := newFakeFeed(t)
	ff.docs["/v3/index.json"] = `{"version":"3.0.0","resources":[]}`
	_, err := newClient(ff, t.TempDir(), &clock{time.Now()}).Load(context.Background())
	if err == nil || !strings.Contains(err.Error(), "VulnerabilityInfo") {
		t.Fatalf("err = %v, want missing VulnerabilityInfo resource", err)
	}
}

func TestParseSeverity(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Errorf("ParseSeverity(HIGH) = %v, %v", s, err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("ParseSeverity(severe) succeeded")
	}
	if !Unknown.AtLeast(Critical) || Moderate.AtLeast(High) || !Critical.AtLeast(High) {
		t.Error("AtLeast ordering wrong")
	}
}
