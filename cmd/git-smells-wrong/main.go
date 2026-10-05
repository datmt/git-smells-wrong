package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/datmt/git-smells-wrong/internal/config"
	"github.com/datmt/git-smells-wrong/internal/engine"
	"github.com/datmt/git-smells-wrong/internal/sandbox"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "git-smells-wrong",
		Short: "Containerized Git sandbox & malicious repo auditor",
		Long: `git-smells-wrong safely clones, inspects, and analyzes untrusted repositories
for malicious delivery vectors (.git/hooks, package lifecycle hooks,
IDE auto-run tasks) without exposing the host environment.`,
		Version: version,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
}

func newScanCmd() *cobra.Command {
	var cfg config.ScanConfig
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a remote repo or local archive",
		Example: `  git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git"
  git-smells-wrong scan --archive="./take-home.zip"
  git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git" --report="./report.json" --format=json
  git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git" --sandbox=docker`,
		Run: func(cmd *cobra.Command, args []string) {
			// Docker delegation: re-exec inside the official image.
			if cfg.Sandbox == "docker" {
				code := sandbox.DelegateToDocker(rawArgs(cmd), cfg.Report)
				os.Exit(code)
			}
			if err := cfg.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, "git-smells-wrong: %v\n", err)
				_ = cmd.Usage()
				os.Exit(2)
			}
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()
			res, err := engine.Run(ctx, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "git-smells-wrong: scan failed: %v\n", err)
				os.Exit(2)
			}
			if cfg.Report != "" {
				if err := os.WriteFile(cfg.Report, []byte(res.Output), 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "git-smells-wrong: write report: %v\n", err)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr, "git-smells-wrong: report written to %s (verdict %s, exit %d)\n",
					cfg.Report, res.Report.Summary.Verdict, res.ExitCode)
			} else {
				fmt.Print(res.Output)
			}
			os.Exit(res.ExitCode)
		},
	}
	cmd.Flags().StringVar(&cfg.Repo, "repo", "", "URL of the remote Git repository to clone and inspect.")
	cmd.Flags().StringVar(&cfg.Archive, "archive", "", "Path to a local .zip or .tar.gz archive.")
	cmd.Flags().StringVar(&cfg.Branch, "branch", "HEAD", "Specific branch/tag to checkout during dynamic trace.")
	cmd.Flags().StringVar(&cfg.Report, "report", "", "File path to write the output report (if empty, prints to STDOUT).")
	cmd.Flags().StringVar(&cfg.Format, "format", "text", "Output format: text, json, or sarif.")
	cmd.Flags().StringVar(&cfg.Sandbox, "sandbox", "native", "Execution backend: native or docker.")
	cmd.Flags().DurationVar(&cfg.Timeout, "timeout", 2*60*1000000000, "Execution timeout for clone and analysis phases.")
	return cmd
}

// rawArgs reconstructs the scan flags as passed on the command line for
// docker delegation (excluding program name and "scan" subcommand).
func rawArgs(cmd *cobra.Command) []string {
	var out []string
	for _, name := range []string{"repo", "archive", "branch", "report", "format", "sandbox", "timeout"} {
		f := cmd.Flags().Lookup(name)
		if f == nil || !f.Changed {
			continue
		}
		out = append(out, "--"+name+"="+f.Value.String())
	}
	return out
}
