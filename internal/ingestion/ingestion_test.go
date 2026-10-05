package ingestion

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractArchiveBlocksZipSlip(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "slip.zip")
	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	fw, err := w.Create("../../evil.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("pwn"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ExtractArchive(arc); err == nil {
		t.Fatal("expected zip-slip error, got nil")
	}
}

func TestExtractArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "ok.zip")
	f, _ := os.Create(arc)
	w := zip.NewWriter(f)
	fw, _ := w.Create("package.json")
	_, _ = fw.Write([]byte(`{"name":"ok"}`))
	w.Close()
	f.Close()
	dest, err := ExtractArchive(arc)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dest)
	if _, err := os.Stat(filepath.Join(dest, "package.json")); err != nil {
		t.Fatalf("expected package.json extracted: %v", err)
	}
}
