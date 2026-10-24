package project

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ErrNotRestored is returned by Load when a project has neither
// obj/project.assets.json nor packages.lock.json.
var ErrNotRestored = errors.New("project not restored, run `dotnet restore`")

// Package is one resolved NuGet package in a project's dependency graph.
type Package struct {
	ID      string
	Version string
	// Direct is true when the project references the package itself.
	Direct bool
	// Via lists the project's top-level dependencies (packages or project
	// references) whose dependency closure contains this package.
	Via        []string
	Frameworks []string
}

// Resolved is the parsed restore output of one project.
type Resolved struct {
	Source   string // file the graph was read from
	Packages []Package
}

// Load reads the resolved dependency graph of the project file at projPath,
// preferring obj/project.assets.json and falling back to packages.lock.json.
func Load(projPath string) (*Resolved, error) {
	dir := filepath.Dir(projPath)
	candidates := []struct {
		path  string
		parse func(io.Reader) ([]Package, error)
	}{
		{filepath.Join(dir, "obj", "project.assets.json"), ParseAssets},
		{filepath.Join(dir, "packages.lock.json"), ParseLock},
	}
	for _, c := range candidates {
		f, err := os.Open(c.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		pkgs, err := c.parse(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.path, err)
		}
		return &Resolved{Source: c.path, Packages: pkgs}, nil
	}
	return nil, ErrNotRestored
}

type node struct {
	id, version string
	isPackage   bool
	deps        []string // dependency IDs, lower-cased
}

// graph is the resolved dependency graph for one target framework.
type graph struct {
	nodes map[string]*node // keyed by lower-cased ID
	roots []string         // lower-cased IDs of top-level dependencies
}

// ParseAssets parses obj/project.assets.json.
func ParseAssets(r io.Reader) ([]Package, error) {
	var f struct {
		Version int `json:"version"`
		Targets map[string]map[string]struct {
			Type         string            `json:"type"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"targets"`
		ProjectFileDependencyGroups map[string][]string `json:"projectFileDependencyGroups"`
	}
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, err
	}
	if f.Targets == nil {
		return nil, errors.New("no \"targets\" section; not a project.assets.json file?")
	}
	graphs := map[string]graph{}
	for tfm, libs := range f.Targets {
		if strings.Contains(tfm, "/") { // RID-specific target duplicates the base one
			continue
		}
		g := graph{nodes: map[string]*node{}}
		for key, lib := range libs {
			id, ver, ok := strings.Cut(key, "/")
			if !ok {
				return nil, fmt.Errorf("target %s: malformed library key %q", tfm, key)
			}
			g.nodes[strings.ToLower(id)] = &node{id: id, version: ver, isPackage: lib.Type == "package", deps: lowerKeys(lib.Dependencies)}
		}
		for _, dep := range f.ProjectFileDependencyGroups[tfm] {
			// Entries look like "Newtonsoft.Json >= 13.0.1".
			id, _, _ := strings.Cut(strings.TrimSpace(dep), " ")
			g.roots = append(g.roots, strings.ToLower(id))
		}
		graphs[tfm] = g
	}
	return flatten(graphs), nil
}

// ParseLock parses packages.lock.json.
func ParseLock(r io.Reader) ([]Package, error) {
	var f struct {
		Version      int `json:"version"`
		Dependencies map[string]map[string]struct {
			Type         string            `json:"type"`
			Resolved     string            `json:"resolved"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"dependencies"`
	}
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, err
	}
	if f.Dependencies == nil {
		return nil, errors.New("no \"dependencies\" section; not a packages.lock.json file?")
	}
	graphs := map[string]graph{}
	for tfm, deps := range f.Dependencies {
		if strings.Contains(tfm, "/") {
			continue
		}
		g := graph{nodes: map[string]*node{}}
		for id, d := range deps {
			lid := strings.ToLower(id)
			g.nodes[lid] = &node{id: id, version: d.Resolved, isPackage: d.Type != "Project", deps: lowerKeys(d.Dependencies)}
			if d.Type == "Direct" || d.Type == "Project" {
				g.roots = append(g.roots, lid)
			}
		}
		graphs[tfm] = g
	}
	return flatten(graphs), nil
}

func lowerKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, strings.ToLower(k))
	}
	return out
}

// flatten walks each framework's graph from its roots and merges the
// packages of all frameworks, keyed by ID and version.
func flatten(graphs map[string]graph) []Package {
	merged := map[string]*Package{}
	tfms := make([]string, 0, len(graphs))
	for tfm := range graphs {
		tfms = append(tfms, tfm)
	}
	slices.Sort(tfms)

	for _, tfm := range tfms {
		g := graphs[tfm]
		direct := map[string]bool{}
		via := map[string][]string{}
		for _, root := range g.roots {
			rn, ok := g.nodes[root]
			if !ok {
				continue
			}
			direct[root] = true
			seen := map[string]bool{root: true}
			stack := slices.Clone(rn.deps)
			for len(stack) > 0 {
				id := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if seen[id] {
					continue
				}
				seen[id] = true
				if n, ok := g.nodes[id]; ok {
					via[id] = append(via[id], rn.id)
					stack = append(stack, n.deps...)
				}
			}
		}
		for lid, n := range g.nodes {
			if !n.isPackage {
				continue
			}
			key := lid + "/" + strings.ToLower(n.version)
			p := merged[key]
			if p == nil {
				p = &Package{ID: n.id, Version: n.version}
				merged[key] = p
			}
			p.Direct = p.Direct || direct[lid]
			p.Via = append(p.Via, via[lid]...)
			p.Frameworks = append(p.Frameworks, tfm)
		}
	}

	out := make([]Package, 0, len(merged))
	for _, p := range merged {
		slices.Sort(p.Via)
		p.Via = slices.Compact(p.Via)
		out = append(out, *p)
	}
	slices.SortFunc(out, func(a, b Package) int {
		if c := strings.Compare(strings.ToLower(a.ID), strings.ToLower(b.ID)); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out
}
