// Command nugetwatch scans restored .NET projects for NuGet packages with
// known vulnerabilities, using NuGet's public vulnerability feed.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Erion14/nugetwatch/internal/feed"
	"github.com/Erion14/nugetwatch/internal/notify"
	"github.com/Erion14/nugetwatch/internal/report"
	"github.com/Erion14/nugetwatch/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version string

const (
	exitClean = 0
	exitVulns = 1
	exitError = 2
)

const usage = `nugetwatch scans restored .NET projects for vulnerable NuGet packages.

Usage:
  nugetwatch scan [paths...] [flags]   scan solutions, projects or directories
  nugetwatch version                   print the version

With no paths, scan reads one path per line (# starts a comment) from
nugetwatch/projects in the config directory: ~/.config on Linux,
~/Library/Application Support on macOS, %AppData% on Windows.

Exit codes: 0 clean, 1 vulnerabilities found, 2 error.

Scan flags:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func toolVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "write the report as JSON")
	sarifOut := fs.Bool("sarif", false, "write the report as SARIF 2.1.0 (GitHub code scanning)")
	doNotify := fs.Bool("notify", false, "send a desktop notification when vulnerabilities are found")
	notifyAlways := fs.Bool("notify-always", false, "send a desktop notification even when the scan is clean")
	failOn := fs.String("fail-on", "low", "minimum severity that counts as a finding: low, moderate, high, critical")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}

	if len(args) == 0 {
		fs.Usage()
		return exitError
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, "nugetwatch", toolVersion())
		return exitClean
	case "help", "-h", "-help", "--help":
		fs.SetOutput(stdout)
		fs.Usage()
		return exitClean
	case "scan":
	default:
		fmt.Fprintf(stderr, "nugetwatch: unknown command %q\n\n", args[0])
		fs.Usage()
		return exitError
	}

	// Allow flags before and after paths.
	var paths []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitClean
			}
			return exitError
		}
		if fs.NArg() == 0 {
			break
		}
		paths = append(paths, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	threshold, err := feed.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "nugetwatch:", err)
		return exitError
	}
	if *jsonOut && *sarifOut {
		fmt.Fprintln(stderr, "nugetwatch: --json and --sarif are mutually exclusive")
		return exitError
	}
	wantNotify := *doNotify || *notifyAlways
	fail := func(err error) int {
		fmt.Fprintln(stderr, "nugetwatch:", err)
		if wantNotify {
			sendNotification(ctx, stderr, "nugetwatch failed", err.Error(), notify.Critical)
		}
		return exitError
	}

	if len(paths) == 0 {
		paths, err = configuredPaths()
		if err != nil {
			return fail(err)
		}
	}

	cacheDir, err := xdgDir("XDG_CACHE_HOME", os.UserCacheDir)
	if err != nil {
		return fail(fmt.Errorf("locating cache directory: %w", err))
	}
	client := &feed.Client{
		ServiceIndex: feed.DefaultServiceIndex,
		CacheDir:     filepath.Join(cacheDir, "nugetwatch"),
		UserAgent:    "nugetwatch/" + toolVersion() + " (+https://github.com/Erion14/nugetwatch)",
	}
	if u := os.Getenv("NUGETWATCH_SERVICE_INDEX"); u != "" {
		client.ServiceIndex = u
	}

	rep, err := scan.Run(ctx, paths, client, min(runtime.NumCPU(), 8))
	if err != nil {
		return fail(err)
	}
	rep.Tool, rep.Version = "nugetwatch", toolVersion()

	if rep.Feed.Stale {
		fmt.Fprintf(stderr, "warning: NuGet vulnerability feed unreachable (%s); using cached data last checked %s\n",
			rep.Feed.StaleReason, rep.Feed.CheckedAt.Local().Format(time.DateTime))
	}
	if rep.Feed.SkippedAdvisories > 0 {
		fmt.Fprintf(stderr, "warning: ignored %d advisories with unparsable version ranges\n", rep.Feed.SkippedAdvisories)
	}

	switch {
	case *jsonOut:
		err = report.WriteJSON(stdout, rep)
	case *sarifOut:
		err = report.WriteSARIF(stdout, rep)
	default:
		err = report.WriteText(stdout, rep, threshold, time.Now())
	}
	if err != nil {
		return fail(fmt.Errorf("writing report: %w", err))
	}

	sum := rep.Summarize(threshold)
	code := exitClean
	if sum.VulnerablePackages > 0 {
		code = exitVulns
	}
	if sum.Failed == sum.Projects {
		fmt.Fprintln(stderr, "nugetwatch: no project could be scanned")
		code = exitError
	}

	if wantNotify && (code != exitClean || *notifyAlways) {
		body := sum.Message()
		if rep.Feed.Stale {
			body += "\n(feed unreachable, using cached data)"
		}
		urgency := notify.Normal
		if sum.BySeverity[feed.Critical]+sum.BySeverity[feed.High] > 0 || code == exitError {
			urgency = notify.Critical
		}
		sendNotification(ctx, stderr, "nugetwatch", body, urgency)
	}
	return code
}

// sendNotification never affects the scan result; failures are only reported.
func sendNotification(ctx context.Context, stderr io.Writer, title, body string, u notify.Urgency) {
	if err := notify.Send(ctx, title, body, u); err != nil {
		fmt.Fprintln(stderr, "warning: notification failed:", err)
	}
}

// xdgDir honours an absolute XDG_* variable on every OS, falling back to the
// platform default (which on Linux already follows XDG).
func xdgDir(env string, fallback func() (string, error)) (string, error) {
	if d := os.Getenv(env); filepath.IsAbs(d) {
		return d, nil
	}
	return fallback()
}

// configuredPaths reads $XDG_CONFIG_HOME/nugetwatch/projects.
func configuredPaths() ([]string, error) {
	dir, err := xdgDir("XDG_CONFIG_HOME", os.UserConfigDir)
	if err != nil {
		return nil, fmt.Errorf("locating config directory: %w", err)
	}
	file := filepath.Join(dir, "nugetwatch", "projects")
	f, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no paths given and %s does not exist; create it with one project path per line", file)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	home, _ := os.UserHomeDir()
	var paths []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "~/"); ok && home != "" {
			line = filepath.Join(home, rest)
		} else if !filepath.IsAbs(line) && home != "" {
			line = filepath.Join(home, line)
		}
		paths = append(paths, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s lists no projects", file)
	}
	return paths, nil
}
