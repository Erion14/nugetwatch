package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/Erion14/nugetwatch/internal/feed"
)

// SARIF 2.1.0, limited to the fields GitHub code scanning uses.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	} `json:"driver"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// securitySeverity maps to GitHub's numeric scale (critical >= 9, high >= 7, medium >= 4).
var securitySeverity = map[feed.Severity]string{feed.Critical: "9.5", feed.High: "8.0", feed.Moderate: "5.5", feed.Low: "2.0"}

func level(s feed.Severity) string {
	switch s {
	case feed.Critical, feed.High:
		return "error"
	case feed.Moderate:
		return "warning"
	}
	return "note"
}

// ruleID uses the advisory ID (e.g. GHSA-xxxx) when the URL ends in one.
func ruleID(url string) string {
	if id := path.Base(url); strings.HasPrefix(id, "GHSA-") || strings.HasPrefix(id, "CVE-") {
		return id
	}
	return url
}

// WriteSARIF writes findings as SARIF, one result per project, package and
// advisory, located at the project file (relative to the working directory).
func WriteSARIF(w io.Writer, r *Report) error {
	run := sarifRun{Results: []sarifResult{}}
	run.Tool.Driver.Name = r.Tool
	run.Tool.Driver.Version = r.Version
	run.Tool.Driver.InformationURI = "https://github.com/Erion14/nugetwatch"
	run.Tool.Driver.Rules = []sarifRule{}
	rules := map[string]bool{}

	for _, p := range r.Projects {
		uri := filepath.ToSlash(displayPath(p.Path))
		for _, f := range p.Findings {
			for _, a := range f.Advisories {
				id := ruleID(a.URL)
				if !rules[id] {
					rules[id] = true
					rule := sarifRule{ID: id, ShortDescription: sarifText{"Vulnerable NuGet package (" + id + ")"}, HelpURI: a.URL,
						Properties: map[string]any{"tags": []string{"security"}}}
					if s, ok := securitySeverity[a.Severity]; ok {
						rule.Properties["security-severity"] = s
					}
					run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
				}
				origin := "direct dependency"
				if !f.Direct {
					origin = "transitive dependency via " + strings.Join(f.Via, ", ")
				}
				res := sarifResult{
					RuleID: id,
					Level:  level(a.Severity),
					Message: sarifText{fmt.Sprintf("%s %s (%s) is affected by %s, severity %s, affected range %s",
						f.Package, f.Version, origin, a.URL, a.Severity, a.AffectedRange)},
				}
				var loc sarifLocation
				loc.PhysicalLocation.ArtifactLocation.URI = uri
				loc.PhysicalLocation.Region.StartLine = 1
				res.Locations = []sarifLocation{loc}
				run.Results = append(run.Results, res)
			}
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}
