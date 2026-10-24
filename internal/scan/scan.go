// Package scan ties discovery, dependency parsing and the vulnerability feed
// together into a report.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/Erion14/nugetwatch/internal/feed"
	"github.com/Erion14/nugetwatch/internal/nugetver"
	"github.com/Erion14/nugetwatch/internal/project"
	"github.com/Erion14/nugetwatch/internal/report"
)

// Run scans every project found under paths. Per-project problems (missing
// path, not restored, unreadable assets file) are recorded in the report;
// only a failure to obtain vulnerability data is returned as an error.
func Run(ctx context.Context, paths []string, client *feed.Client, workers int) (*report.Report, error) {
	type feedResult struct {
		db  *feed.DB
		err error
	}
	feedCh := make(chan feedResult, 1)
	go func() {
		db, err := client.Load(ctx)
		feedCh <- feedResult{db, err}
	}()

	var projects []report.Project
	var files []string
	for _, p := range paths {
		found, err := project.Discover(p)
		switch {
		case err != nil:
			msg := err.Error()
			if errors.Is(err, fs.ErrNotExist) {
				msg = "path not found"
			}
			projects = append(projects, report.Project{Name: filepath.Base(p), Path: p, Error: msg})
		case len(found) == 0:
			projects = append(projects, report.Project{Name: filepath.Base(p), Path: p, Error: "no .csproj/.fsproj/.vbproj files found"})
		}
		files = append(files, found...)
	}
	slices.Sort(files)
	files = slices.Compact(files)

	// Parse restore output with a bounded worker pool.
	resolved := make([]*project.Resolved, len(files))
	errs := make([]error, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range max(1, min(workers, len(files))) {
		wg.Go(func() {
			for i := range jobs {
				resolved[i], errs[i] = project.Load(files[i])
			}
		})
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	fr := <-feedCh
	if fr.err != nil {
		return nil, fmt.Errorf("vulnerability data unavailable: %w", fr.err)
	}
	db := fr.db

	for i, file := range files {
		p := report.Project{
			Name:     strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)),
			Path:     file,
			Findings: []report.Finding{},
		}
		if errs[i] != nil {
			p.Error = errs[i].Error()
			projects = append(projects, p)
			continue
		}
		p.Source = resolved[i].Source
		p.Packages = len(resolved[i].Packages)
		for _, pkg := range resolved[i].Packages {
			v, err := nugetver.Parse(pkg.Version)
			if err != nil {
				p.Warnings = append(p.Warnings, fmt.Sprintf("skipped %s: %v", pkg.ID, err))
				continue
			}
			if f, ok := finding(db, pkg, v); ok {
				p.Findings = append(p.Findings, f)
			}
		}
		slices.SortStableFunc(p.Findings, func(a, b report.Finding) int { return int(b.Severity - a.Severity) })
		projects = append(projects, p)
	}

	return &report.Report{
		Feed: report.Feed{
			Updated:           db.Updated,
			CheckedAt:         db.FetchedAt,
			Stale:             db.Stale,
			StaleReason:       db.StaleReason,
			Requests:          db.Requests,
			SkippedAdvisories: db.Skipped,
		},
		Projects: projects,
	}, nil
}

func finding(db *feed.DB, pkg project.Package, v nugetver.Version) (report.Finding, bool) {
	advs := db.Match(pkg.ID, v)
	if len(advs) == 0 {
		return report.Finding{}, false
	}
	f := report.Finding{Package: pkg.ID, Version: pkg.Version, Direct: pkg.Direct, Via: pkg.Via, Severity: feed.Unknown}
	for _, a := range advs {
		f.Advisories = append(f.Advisories, report.Advisory{URL: a.URL, Severity: a.Severity, AffectedRange: a.Range.String()})
		f.Severity = max(f.Severity, a.Severity)
	}
	slices.SortStableFunc(f.Advisories, func(a, b report.Advisory) int { return int(b.Severity - a.Severity) })
	return f, true
}
