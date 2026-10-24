package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Advisories mirror the real feed's shape; only the base page has data.
const basePage = `{
  "newtonsoft.json": [{"url": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr", "severity": 2, "versions": "(, 13.0.1)"}],
  "system.text.json": [{"url": "https://github.com/advisories/GHSA-hh2w-p6rv-4g7w", "severity": 2, "versions": "[8.0.0, 8.0.4)"}],
  "azure.identity": [{"url": "https://github.com/advisories/GHSA-m5vv-6r4h-3vj9", "severity": 1, "versions": "[1.0.0, 1.10.0)"}]
}`

// env isolates cache, config and PATH, points the tool at a mock feed and
// installs a fake notify-send that appends its arguments to a log file.
// It returns the notification log path.
func env(t *testing.T, feedURL, notifyScript string) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	t.Setenv("NUGETWATCH_SERVICE_INDEX", feedURL)
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(tmp, "notifications.log")
	script := strings.ReplaceAll(notifyScript, "$LOG", log)
	if err := os.WriteFile(filepath.Join(bin, "notify-send"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

const recordingNotifier = "#!/bin/sh\nprintf '%s|' \"$@\" >> \"$LOG\"\necho >> \"$LOG\"\n"

func mockFeed(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		switch r.URL.Path {
		case "/v3/index.json":
			w.Write([]byte(`{"version":"3.0.0","resources":[{"@id":"` + srv.URL + `/v3/vulnerabilities/index.json","@type":"VulnerabilityInfo/6.7.0"}]}`))
		case "/v3/vulnerabilities/index.json":
			w.Write([]byte(`[{"@name":"base","@id":"` + srv.URL + `/base.json","@updated":"2026-10-19T23:33:13Z"},` +
				`{"@name":"update","@id":"` + srv.URL + `/update.json","@updated":"2026-10-24T11:33:49Z"}]`))
		case "/base.json":
			w.Write([]byte(basePage))
		case "/update.json":
			w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func skipUnlessLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("notifications and the fake notify-send script are Linux-only")
	}
}

func TestScanFindsDirectAndTransitiveVulnerabilities(t *testing.T) {
	skipUnlessLinux(t)
	log := env(t, mockFeed(t).URL+"/v3/index.json", recordingNotifier)

	code, out, errOut := runCLI("scan", "testdata/workspace", "--notify")
	if code != exitVulns {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitVulns, out, errOut)
	}
	for _, want := range []string{
		"Newtonsoft.Json 12.0.1  (direct)",
		"System.Text.Json 8.0.0  (transitive via Azure.Identity)",
		"affected [8.0.0, 8.0.4)  https://github.com/advisories/GHSA-hh2w-p6rv-4g7w",
		"project not restored, run `dotnet restore`",
		"2 vulnerable packages across 1 project (2 High); 1 project not scanned",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Azure.Identity 1.10.0 sits exactly on the excluded upper bound of [1.0.0, 1.10.0).
	if strings.Contains(out, "Azure.Identity 1.10.0") {
		t.Errorf("Azure.Identity 1.10.0 reported but is outside the advisory range:\n%s", out)
	}
	want := "--app-name=nugetwatch|--urgency=critical|nugetwatch|2 vulnerable packages across 1 project (2 High); 1 project not scanned|\n"
	if got := readLog(t, log); got != want {
		t.Errorf("notification = %q, want %q", got, want)
	}
}

func TestJSONOutputAndFailOnThreshold(t *testing.T) {
	env(t, mockFeed(t).URL+"/v3/index.json", recordingNotifier)

	code, out, errOut := runCLI("scan", "--json", "--fail-on", "critical", "testdata/workspace/VulnerableApp/VulnerableApp.csproj")
	if code != exitClean {
		t.Fatalf("exit code = %d, want 0 (only High findings, threshold critical); stderr: %s", code, errOut)
	}
	var rep struct {
		Projects []struct {
			Name     string `json:"name"`
			Source   string `json:"source"`
			Findings []struct {
				Package    string   `json:"package"`
				Direct     bool     `json:"direct"`
				Via        []string `json:"via"`
				Severity   string   `json:"severity"`
				Advisories []map[string]any
			} `json:"findings"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rep.Projects) != 1 || len(rep.Projects[0].Findings) != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	for _, f := range rep.Projects[0].Findings {
		if f.Severity != "High" {
			t.Errorf("%s severity = %q, want High", f.Package, f.Severity)
		}
		if f.Package == "System.Text.Json" && (f.Direct || len(f.Via) != 1 || f.Via[0] != "Azure.Identity") {
			t.Errorf("System.Text.Json provenance = direct:%v via:%v", f.Direct, f.Via)
		}
		for _, a := range f.Advisories {
			if len(a) != 3 || a["affectedRange"] == nil || a["url"] == nil || a["severity"] == nil {
				t.Errorf("advisory has unexpected fields (no fixed version may be invented): %v", a)
			}
		}
	}
}

func TestConfigFileAndCleanNotify(t *testing.T) {
	skipUnlessLinux(t)
	log := env(t, mockFeed(t).URL+"/v3/index.json", recordingNotifier)
	cfg := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "nugetwatch", "projects")
	abs, _ := filepath.Abs("testdata/workspace/VulnerableApp")
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	os.WriteFile(cfg, []byte("# my projects\n\n"+abs+"\n"), 0o644)

	// Clean relative to the threshold: --notify stays silent...
	if code, out, _ := runCLI("scan", "--notify", "--fail-on", "critical"); code != exitClean || !strings.Contains(out, "VulnerableApp") {
		t.Fatalf("config scan exit = %d, output:\n%s", code, out)
	}
	if got := readLog(t, log); got != "" {
		t.Errorf("--notify on a clean run sent %q", got)
	}
	// ...while --notify-always reports the clean result.
	runCLI("scan", "--notify-always", "--fail-on", "critical")
	if got := readLog(t, log); !strings.Contains(got, "|No known vulnerable packages in 1 project|") {
		t.Errorf("--notify-always notification = %q", got)
	}
}

func TestNotificationFailureDoesNotChangeExitCode(t *testing.T) {
	skipUnlessLinux(t)
	env(t, mockFeed(t).URL+"/v3/index.json", "#!/bin/sh\necho 'no notification daemon' >&2\nexit 1\n")
	code, _, errOut := runCLI("scan", "testdata/workspace/VulnerableApp", "--notify")
	if code != exitVulns {
		t.Errorf("exit code = %d, want %d", code, exitVulns)
	}
	if !strings.Contains(errOut, "notification failed") || !strings.Contains(errOut, "no notification daemon") {
		t.Errorf("stderr does not explain notification failure: %q", errOut)
	}
}

func TestUnreachableFeedWithoutCacheIsAnError(t *testing.T) {
	srv := mockFeed(t)
	url := srv.URL + "/v3/index.json"
	srv.Close()
	env(t, url, recordingNotifier)
	code, _, errOut := runCLI("scan", "testdata/workspace/VulnerableApp")
	if code != exitError || !strings.Contains(errOut, "vulnerability data unavailable") {
		t.Errorf("exit = %d, stderr = %q; want 2 and a clear message", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	env(t, "http://127.0.0.1:0/unused", recordingNotifier)
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"scan", "--fail-on", "severe", "x"},
		{"scan", "--json", "--sarif", "x"},
		{"scan"}, // no config file
	} {
		if code, _, _ := runCLI(args...); code != exitError {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}
