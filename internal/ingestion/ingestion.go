package ingestion

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SafeClone clones repoURL into a fresh temp dir while suppressing hook
// templates. It always passes --template=/dev/null so that global or
// system-level hook templates are not copied into the working directory.
// The caller is responsible for removing the returned directory.
func SafeClone(ctx context.Context, repoURL, branch string, timeout time.Duration) (string, error) {
	dest, err := os.MkdirTemp("", "git-smells-wrong-clone-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"clone", "--template=/dev/null", "--no-hardlinks"}
	if branch != "" && branch != "HEAD" {
		args = append(args, "--branch", branch)
	}
	args = append(args, repoURL, dest)

	// Clone into an empty dir: git requires a non-existent or empty target.
	// MkdirTemp already created dest, which git accepts (empty dir).
	cmd := exec.CommandContext(cctx, "git", args...)
	// Harden git against prompt hangs and unsafe protocols where possible.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(dest)
		return "", fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return dest, nil
}

// ExtractArchive extracts a .zip or .tar.gz archive into a fresh temp dir
// with strict Zip-Slip protection. Returns the temp dir path.
func ExtractArchive(archivePath string) (string, error) {
	dest, err := os.MkdirTemp("", "git-smells-wrong-archive-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	if err := extract(archivePath, dest); err != nil {
		os.RemoveAll(dest)
		return "", err
	}
	return dest, nil
}

func extract(archivePath, dest string) error {
	lower := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZip(archivePath, dest)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return extractTarGz(archivePath, dest)
	default:
		return fmt.Errorf("unsupported archive format %q: expected .zip or .tar.gz", archivePath)
	}
}

// safeJoin resolves name inside dest and rejects directory traversal,
// absolute paths, and symlink escapes (Zip-Slip).
func safeJoin(dest, name string) (string, error) {
	cleaned := filepath.Clean(name)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("zip-slip blocked: absolute path %q", name)
	}
	// filepath.Clean strips leading "./"; check traversal on the cleaned path.
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("zip-slip blocked: traversal path %q", name)
	}
	target := filepath.Join(dest, cleaned)
	// Belt-and-suspenders: ensure target is still within dest after join.
	rel, err := filepath.Rel(dest, target)
	if err != nil {
		return "", fmt.Errorf("zip-slip blocked: %q", name)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("zip-slip blocked: %q escapes destination", name)
	}
	return target, nil
}

func extractZip(archivePath, dest string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		// Directories: create and continue.
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %q: %w", target, err)
			}
			continue
		}
		// Reject symlinks inside zips: only regular files are materialized.
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("zip-slip blocked: symlink entry %q", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent: %w", err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create file %q: %w", target, err)
		}
		_, copyErr := io.Copy(out, rc)
		closeErr1 := out.Close()
		closeErr2 := rc.Close()
		if copyErr != nil {
			return fmt.Errorf("extract %q: %w", f.Name, copyErr)
		}
		if closeErr1 != nil {
			return fmt.Errorf("close %q: %w", target, closeErr1)
		}
		if closeErr2 != nil {
			return fmt.Errorf("close zip entry: %w", closeErr2)
		}
	}
	return nil
}

func extractTarGz(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %q: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent: %w", err)
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				return fmt.Errorf("create file %q: %w", target, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("extract %q: %w", hdr.Name, err)
			}
			out.Close()
		default:
			// Refuse symlinks, hardlinks, devices, fifos — never materialize them.
			return fmt.Errorf("blocked unsafe tar entry %q (type %c): only regular files and directories are allowed", hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}
