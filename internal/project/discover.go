// Package project finds .NET projects and reads their resolved NuGet
// dependency graph from restore output (obj/project.assets.json or
// packages.lock.json), without invoking the dotnet CLI.
package project

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var projectExts = []string{".csproj", ".fsproj", ".vbproj"}

func isProjectFile(p string) bool {
	return slices.Contains(projectExts, strings.ToLower(filepath.Ext(p)))
}

// Discover returns the absolute, sorted, de-duplicated project file paths
// referenced by path, which may be a solution (.sln/.slnx), a project file,
// or a directory (searched recursively, skipping bin, obj and hidden dirs).
func Discover(path string) ([]string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	var found []string
	switch ext := strings.ToLower(filepath.Ext(abs)); {
	case fi.IsDir():
		found, err = walkDir(abs)
	case ext == ".sln":
		found, err = parseSln(abs)
	case ext == ".slnx":
		found, err = parseSlnx(abs)
	case isProjectFile(abs):
		found = []string{abs}
	default:
		return nil, fmt.Errorf("%s: not a solution, project file or directory", path)
	}
	if err != nil {
		return nil, err
	}
	slices.Sort(found)
	return slices.Compact(found), nil
}

func walkDir(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) && p != root {
				return nil
			}
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "bin" || name == "obj" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if isProjectFile(p) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// Project("{FAE04EC0-...}") = "Name", "rel\path\Name.csproj", "{GUID}"
var slnProjectLine = regexp.MustCompile(`^Project\("\{[^}]*\}"\)\s*=\s*"[^"]*"\s*,\s*"([^"]+)"`)

func parseSln(sln string) ([]string, error) {
	f, err := os.Open(sln)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := slnProjectLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m != nil && isProjectFile(m[1]) {
			out = append(out, resolveRel(sln, m[1]))
		}
	}
	return out, sc.Err()
}

func parseSlnx(slnx string) ([]string, error) {
	f, err := os.Open(slnx)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	dec := xml.NewDecoder(f)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", slnx, err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "Project" {
			for _, a := range se.Attr {
				if a.Name.Local == "Path" && isProjectFile(a.Value) {
					out = append(out, resolveRel(slnx, a.Value))
				}
			}
		}
	}
}

// resolveRel resolves a solution-relative path, which uses Windows separators.
func resolveRel(sln, rel string) string {
	rel = strings.ReplaceAll(rel, `\`, "/")
	return filepath.Join(filepath.Dir(sln), filepath.FromSlash(rel))
}
