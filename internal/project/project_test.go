package project

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Two frameworks; net8.0 also has a RID-specific target that must not
// double-count. Lib is a project reference that brings in its own packages.
const assetsJSON = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Microsoft.Identity.Web/2.0.0": {"type": "package", "dependencies": {"Microsoft.IdentityModel.JsonWebTokens": "6.0.0"}},
      "Microsoft.IdentityModel.JsonWebTokens/6.0.0": {"type": "package", "dependencies": {"system.text.json": "8.0.0"}},
      "System.Text.Json/8.0.0": {"type": "package"},
      "Serilog/3.0.0": {"type": "package"},
      "Lib/1.0.0": {"type": "project", "dependencies": {"Newtonsoft.Json": "12.0.1", "System.Text.Json": "8.0.0"}},
      "Newtonsoft.Json/12.0.1": {"type": "package"}
    },
    "net8.0/linux-x64": {
      "Serilog/3.0.0": {"type": "package"},
      "Extra.Runtime/1.0.0": {"type": "package"}
    },
    "net6.0": {
      "System.Text.Json/6.0.0": {"type": "package"},
      "Serilog/3.0.0": {"type": "package", "dependencies": {"System.Text.Json": "6.0.0"}}
    }
  },
  "projectFileDependencyGroups": {
    "net8.0": ["Lib >= 1.0.0", "Microsoft.Identity.Web >= 2.0.0", "Serilog >= 3.0.0"],
    "net6.0": ["Serilog >= 3.0.0"]
  }
}`

func find(t *testing.T, pkgs []Package, id, version string) Package {
	t.Helper()
	for _, p := range pkgs {
		if p.ID == id && p.Version == version {
			return p
		}
	}
	t.Fatalf("package %s %s not found in %+v", id, version, pkgs)
	return Package{}
}

func TestParseAssetsResolvesTransitivePackages(t *testing.T) {
	pkgs, err := ParseAssets(strings.NewReader(assetsJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 6 {
		t.Errorf("got %d packages, want 6 (projects and RID-only entries excluded): %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.ID == "Lib" || p.ID == "Extra.Runtime" {
			t.Errorf("unexpected package %s", p.ID)
		}
	}

	stj8 := find(t, pkgs, "System.Text.Json", "8.0.0")
	if stj8.Direct {
		t.Error("System.Text.Json 8.0.0 should be transitive")
	}
	if want := []string{"Lib", "Microsoft.Identity.Web"}; !slices.Equal(stj8.Via, want) {
		t.Errorf("System.Text.Json 8.0.0 via = %v, want %v", stj8.Via, want)
	}
	if want := []string{"net8.0"}; !slices.Equal(stj8.Frameworks, want) {
		t.Errorf("frameworks = %v, want %v", stj8.Frameworks, want)
	}

	stj6 := find(t, pkgs, "System.Text.Json", "6.0.0")
	if want := []string{"Serilog"}; !slices.Equal(stj6.Via, want) {
		t.Errorf("System.Text.Json 6.0.0 via = %v, want %v", stj6.Via, want)
	}

	if nj := find(t, pkgs, "Newtonsoft.Json", "12.0.1"); nj.Direct || !slices.Equal(nj.Via, []string{"Lib"}) {
		t.Errorf("Newtonsoft.Json = %+v, want transitive via Lib", nj)
	}

	serilog := find(t, pkgs, "Serilog", "3.0.0")
	if !serilog.Direct || len(serilog.Via) != 0 {
		t.Errorf("Serilog = %+v, want direct with no via", serilog)
	}
	if want := []string{"net6.0", "net8.0"}; !slices.Equal(serilog.Frameworks, want) {
		t.Errorf("Serilog frameworks = %v, want %v", serilog.Frameworks, want)
	}
}

func TestParseAssetsRejectsGarbage(t *testing.T) {
	for _, in := range []string{`not json`, `{"version": 3}`, `{"targets": {"net8.0": {"NoSlash": {"type": "package"}}}}`} {
		if _, err := ParseAssets(strings.NewReader(in)); err == nil {
			t.Errorf("ParseAssets(%q) succeeded, want error", in)
		}
	}
}

const lockJSON = `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"},
      "Lib": {"type": "Project", "dependencies": {"System.Text.Json": "[8.0.0, )"}},
      "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"}
    }
  }
}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPrefersAssetsThenLockFile(t *testing.T) {
	dir := t.TempDir()

	both := filepath.Join(dir, "Both", "Both.csproj")
	writeFile(t, both, "<Project/>")
	writeFile(t, filepath.Join(dir, "Both", "obj", "project.assets.json"), assetsJSON)
	writeFile(t, filepath.Join(dir, "Both", "packages.lock.json"), lockJSON)
	res, err := Load(both)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.Source) != "project.assets.json" || len(res.Packages) != 6 {
		t.Errorf("Load(Both) used %s with %d packages, want project.assets.json with 6", res.Source, len(res.Packages))
	}

	lockOnly := filepath.Join(dir, "LockOnly", "LockOnly.csproj")
	writeFile(t, lockOnly, "<Project/>")
	writeFile(t, filepath.Join(dir, "LockOnly", "packages.lock.json"), lockJSON)
	res, err = Load(lockOnly)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.Source) != "packages.lock.json" {
		t.Errorf("Load(LockOnly) used %s", res.Source)
	}
	stj := find(t, res.Packages, "System.Text.Json", "8.0.0")
	if stj.Direct || !slices.Equal(stj.Via, []string{"Lib"}) {
		t.Errorf("lock System.Text.Json = %+v, want transitive via Lib", stj)
	}
	if !find(t, res.Packages, "Newtonsoft.Json", "12.0.1").Direct {
		t.Error("lock Newtonsoft.Json should be direct")
	}

	bare := filepath.Join(dir, "Bare", "Bare.csproj")
	writeFile(t, bare, "<Project/>")
	if _, err := Load(bare); !errors.Is(err, ErrNotRestored) {
		t.Errorf("Load(Bare) error = %v, want ErrNotRestored", err)
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "src", "App", "App.csproj"), "")
	writeFile(t, filepath.Join(dir, "src", "Lib", "Lib.fsproj"), "")
	writeFile(t, filepath.Join(dir, "src", "App", "obj", "Ignored.csproj"), "")
	writeFile(t, filepath.Join(dir, "src", "App", "bin", "Ignored.csproj"), "")
	writeFile(t, filepath.Join(dir, ".git", "Ignored.csproj"), "")
	writeFile(t, filepath.Join(dir, "App.sln"), "\ufeff\nMicrosoft Visual Studio Solution File, Format Version 12.00\n"+
		`Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "src\App\App.csproj", "{4336A8D1-4D5A-4B8E-910C-65FE796C905D}"`+"\nEndProject\n"+
		`Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "Solution Items", "Solution Items", "{11111111-1111-1111-1111-111111111111}"`+"\nEndProject\n")
	writeFile(t, filepath.Join(dir, "App.slnx"), `<Solution><Folder Name="/src/"><Project Path="src/Lib/Lib.fsproj" /></Folder></Solution>`)

	app := filepath.Join(dir, "src", "App", "App.csproj")
	lib := filepath.Join(dir, "src", "Lib", "Lib.fsproj")
	tests := []struct {
		path string
		want []string
	}{
		{dir, []string{app, lib}},
		{filepath.Join(dir, "App.sln"), []string{app}},
		{filepath.Join(dir, "App.slnx"), []string{lib}},
		{app, []string{app}},
	}
	for _, tt := range tests {
		got, err := Discover(tt.path)
		if err != nil {
			t.Fatalf("Discover(%s): %v", tt.path, err)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("Discover(%s) = %v, want %v", tt.path, got, tt.want)
		}
	}

	if _, err := Discover(filepath.Join(dir, "missing")); err == nil {
		t.Error("Discover(missing) succeeded")
	}
	writeFile(t, filepath.Join(dir, "notes.txt"), "")
	if _, err := Discover(filepath.Join(dir, "notes.txt")); err == nil {
		t.Error("Discover(notes.txt) succeeded")
	}
}
