package engine

import (
	"context"
	"fmt"
	"os"

	"github.com/yourorg/git-smells-wrong/internal/config"
	"github.com/yourorg/git-smells-wrong/internal/ingestion"
	"github.com/yourorg/git-smells-wrong/internal/report"
	"github.com/yourorg/git-smells-wrong/internal/rules"
	"github.com/yourorg/git-smells-wrong/internal/tracer"
)

// Result bundles the rendered output with its exit code.
type Result struct {
	Report   report.ScanReport
	Output   string
	ExitCode int
}

// Run executes the full scan pipeline: ingest → static rules → dry-run
// trace → report. It cleans up any temp working directory it created.
func Run(ctx context.Context, cfg config.ScanConfig) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	workDir, cleanup, err := ingest(ctx, &cfg)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	findings, err := rules.ScanAll(workDir)
	if err != nil {
		return Result{}, fmt.Errorf("static analysis: %w", err)
	}
	trace := tracer.DryRun(workDir)

	rep := report.Build(cfg.TargetLabel(), cfg.Branch, findings, trace)
	out, err := report.Render(rep, cfg.Format)
	if err != nil {
		return Result{}, err
	}
	return Result{Report: rep, Output: out, ExitCode: rep.Summary.ExitCode}, nil
}

func ingest(ctx context.Context, cfg *config.ScanConfig) (string, func(), error) {
	noop := func() {}
	if cfg.Repo != "" {
		dir, err := ingestion.SafeClone(ctx, cfg.Repo, cfg.Branch, cfg.Timeout)
		if err != nil {
			return "", noop, err
		}
		return dir, func() { os.RemoveAll(dir) }, nil
	}
	// Archive path: must exist.
	if _, err := os.Stat(cfg.Archive); err != nil {
		return "", noop, fmt.Errorf("archive not found: %w", err)
	}
	dir, err := ingestion.ExtractArchive(cfg.Archive)
	if err != nil {
		return "", noop, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}
