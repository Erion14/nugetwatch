// Package report holds scan results and renders them as text, JSON or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Erion14/nugetwatch/internal/feed"
)

// Report is the result of one scan.
type Report struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Feed     Feed      `json:"feed"`
	Projects []Project `json:"projects"`
}

// Feed describes the vulnerability data used.
type Feed struct {
	Updated           time.Time `json:"updated"`   // when NuGet last published data
	CheckedAt         time.Time `json:"checkedAt"` // when the server last confirmed our copy
	Stale             bool      `json:"stale"`
	StaleReason       string    `json:"staleReason,omitempty"`
	Requests          int       `json:"requests"`
	SkippedAdvisories int       `json:"skippedAdvisories,omitempty"`
}

// Project is the scan result of one project file.
type Project struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Source   string    `json:"source,omitempty"` // assets or lock file read
	Error    string    `json:"error,omitempty"`  // set when the project could not be scanned
	Packages int       `json:"packages"`
	Findings []Finding `json:"findings"`
	Warnings []string  `json:"warnings,omitempty"`
}

// Finding is a resolved package version with at least one matching advisory.
type Finding struct {
	Package    string        `json:"package"`
	Version    string        `json:"version"`
	Direct     bool          `json:"direct"`
	Via        []string      `json:"via,omitempty"`
	Severity   feed.Severity `json:"severity"` // highest advisory severity
	Advisories []Advisory    `json:"advisories"`
}

// Advisory is a matched advisory. The feed provides no fixed version, so none is reported.
type Advisory struct {
	URL           string        `json:"url"`
	Severity      feed.Severity `json:"severity"`
	AffectedRange string        `json:"affectedRange"`
}

// Qualifies reports whether any advisory of f meets the threshold.
func (f Finding) Qualifies(min feed.Severity) bool {
	return slices.ContainsFunc(f.Advisories, func(a Advisory) bool { return a.Severity.AtLeast(min) })
}

// Summary aggregates a report for exit codes and notifications.
type Summary struct {
	Projects           int // project entries, including failed ones
	Failed             int // projects that could not be scanned
	VulnerableProjects int
	VulnerablePackages int // distinct package@version across projects
	BySeverity         map[feed.Severity]int
	Packages           []PackageHit // one per distinct package@version, highest severity first
}

// PackageHit is a vulnerable package@version and the projects that resolve it.
type PackageHit struct {
	Package  string
	Version  string
	Severity feed.Severity
	Projects []string
}

// Summarize counts findings that meet the severity threshold.
func (r *Report) Summarize(min feed.Severity) Summary {
	s := Summary{Projects: len(r.Projects), BySeverity: map[feed.Severity]int{}}
	seen := map[string]int{} // package@version -> index into s.Packages
	for _, p := range r.Projects {
		if p.Error != "" {
			s.Failed++
			continue
		}
		vulnerable := false
		for _, f := range p.Findings {
			if !f.Qualifies(min) {
				continue
			}
			vulnerable = true
			key := strings.ToLower(f.Package + "@" + f.Version)
			i, ok := seen[key]
			if !ok {
				i = len(s.Packages)
				seen[key] = i
				s.Packages = append(s.Packages, PackageHit{Package: f.Package, Version: f.Version, Severity: f.Severity})
				s.VulnerablePackages++
				s.BySeverity[f.Severity]++
			}
			if hit := &s.Packages[i]; !slices.Contains(hit.Projects, p.Name) {
				hit.Projects = append(hit.Projects, p.Name)
			}
		}
		if vulnerable {
			s.VulnerableProjects++
		}
	}
	slices.SortStableFunc(s.Packages, func(a, b PackageHit) int { return int(b.Severity - a.Severity) })
	return s
}

// Details lists each vulnerable package with the projects that use it, one per
// line, e.g. "High AutoMapper 16.1.1: Api, Worker +2 more". Output is capped so
// it stays readable in a desktop notification.
func (s Summary) Details() string {
	const maxPackages, maxProjects = 5, 4
	var lines []string
	for i, h := range s.Packages {
		if i == maxPackages {
			lines = append(lines, fmt.Sprintf("+%s", plural(len(s.Packages)-maxPackages, "more package")))
			break
		}
		names := h.Projects
		more := ""
		if len(names) > maxProjects {
			names, more = names[:maxProjects], fmt.Sprintf(" +%d more", len(names)-maxProjects)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s: %s%s", h.Severity, h.Package, h.Version, strings.Join(names, ", "), more))
	}
	return strings.Join(lines, "\n")
}

// Message is a one-line summary, e.g.
// "2 vulnerable packages across 1 project (1 Critical, 1 High)".
func (s Summary) Message() string {
	var b strings.Builder
	if s.VulnerablePackages == 0 {
		fmt.Fprintf(&b, "No known vulnerable packages in %s", plural(s.Projects-s.Failed, "project"))
	} else {
		fmt.Fprintf(&b, "%s across %s", plural(s.VulnerablePackages, "vulnerable package"), plural(s.VulnerableProjects, "project"))
		var parts []string
		for _, sev := range []feed.Severity{feed.Critical, feed.High, feed.Moderate, feed.Low, feed.Unknown} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
	}
	if s.Failed > 0 {
		fmt.Fprintf(&b, "; %s not scanned", plural(s.Failed, "project"))
	}
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable report grouped by project.
func WriteText(w io.Writer, r *Report, min feed.Severity, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range r.Projects {
		switch {
		case p.Error != "":
			fmt.Fprintf(tw, "ERROR\t%s\t%s: %s\n", p.Name, displayPath(p.Path), p.Error)
		case len(p.Findings) == 0:
			fmt.Fprintf(tw, "ok\t%s\t%d packages\n", p.Name, p.Packages)
		default:
			fmt.Fprintf(tw, "VULN\t%s\t%d packages, %d vulnerable\t%s\n", p.Name, p.Packages, len(p.Findings), displayPath(p.Path))
		}
		for _, warn := range p.Warnings {
			fmt.Fprintf(tw, "\t  warning: %s\n", warn)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, p := range r.Projects {
		if len(p.Findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s (%s)\n", p.Name, displayPath(p.Path))
		for _, f := range p.Findings {
			origin := "direct"
			if !f.Direct {
				origin = "transitive"
			}
			if len(f.Via) > 0 {
				origin += " via " + strings.Join(f.Via, ", ")
			}
			fmt.Fprintf(w, "  %-9s %s %s  (%s)\n", f.Severity, f.Package, f.Version, origin)
			for _, a := range f.Advisories {
				fmt.Fprintf(w, "            %-9s affected %s  %s\n", a.Severity, a.AffectedRange, a.URL)
			}
		}
	}

	fmt.Fprintf(w, "\n%s\n", r.Summarize(min).Message())
	freshness := plural(r.Feed.Requests, "network request")
	if r.Feed.Stale {
		freshness = "STALE: feed unreachable, using cached data"
	}
	fmt.Fprintf(w, "Vulnerability data: NuGet feed published %s, last checked %s ago (%s)\n",
		r.Feed.Updated.UTC().Format("2006-01-02 15:04 MST"), age(now.Sub(r.Feed.CheckedAt)), freshness)
	return nil
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "<1m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// displayPath shows p relative to the working directory when it is below it.
func displayPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}
