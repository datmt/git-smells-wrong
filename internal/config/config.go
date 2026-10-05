package config

import (
	"fmt"
	"time"
)

// ScanConfig holds all runtime options for a `git-smells-wrong scan` invocation.
// Both the native binary and the Docker image share these flags.
type ScanConfig struct {
	Repo    string
	Archive string
	Branch  string
	Report  string
	Format  string
	Sandbox string
	Timeout time.Duration
}

// Validate checks flag combinations and value ranges.
func (c *ScanConfig) Validate() error {
	if c.Repo == "" && c.Archive == "" {
		return fmt.Errorf("either --repo or --archive must be provided")
	}
	if c.Repo != "" && c.Archive != "" {
		return fmt.Errorf("only one of --repo or --archive may be provided")
	}
	switch c.Format {
	case "text", "json", "sarif":
	default:
		return fmt.Errorf("invalid --format %q: must be one of text, json, sarif", c.Format)
	}
	switch c.Sandbox {
	case "native", "docker":
	default:
		return fmt.Errorf("invalid --sandbox %q: must be one of native, docker", c.Sandbox)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if c.Branch == "" {
		c.Branch = "HEAD"
	}
	return nil
}

// TargetLabel returns a human-readable scan target for reports.
func (c *ScanConfig) TargetLabel() string {
	if c.Repo != "" {
		return c.Repo
	}
	return c.Archive
}
