package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/datmt/git-smells-wrong/internal/rules"
	"github.com/datmt/git-smells-wrong/internal/tracer"
)

// Exit codes per PRD §5.2C.
const (
	ExitClean    = 0
	ExitWarning  = 1
	ExitCritical = 2
)

// ScanReport is the machine-readable result of a scan.
type ScanReport struct {
	Target    string             `json:"target"`
	Branch    string             `json:"branch"`
	Timestamp time.Time          `json:"timestamp"`
	Findings  []rules.Finding    `json:"findings"`
	Trace     tracer.TraceResult `json:"trace"`
	Summary   Summary            `json:"summary"`
}

type Summary struct {
	Critical int    `json:"critical"`
	Warning  int    `json:"warning"`
	Info     int    `json:"info"`
	ExitCode int    `json:"exit_code"`
	Verdict  string `json:"verdict"`
}

// Build assembles a report and computes the exit code.
func Build(target, branch string, findings []rules.Finding, trace tracer.TraceResult) ScanReport {
	if findings == nil {
		findings = []rules.Finding{}
	}
	s := Summary{}
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			s.Critical++
		case rules.SeverityWarning:
			s.Warning++
		default:
			s.Info++
		}
	}
	switch {
	case s.Critical > 0:
		s.ExitCode = ExitCritical
		s.Verdict = "CRITICAL"
	case s.Warning > 0:
		s.ExitCode = ExitWarning
		s.Verdict = "WARNING"
	default:
		s.ExitCode = ExitClean
		s.Verdict = "CLEAN"
	}
	return ScanReport{
		Target:    target,
		Branch:    branch,
		Timestamp: time.Now().UTC(),
		Findings:  findings,
		Trace:     trace,
		Summary:   s,
	}
}

// Render serializes the report in the requested format ("text", "json", "sarif").
func Render(r ScanReport, format string) (string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "sarif":
		return renderSARIF(r)
	case "text", "":
		return renderText(r), nil
	default:
		return "", fmt.Errorf("unknown format %q", format)
	}
}

// --- Terminal UI (colored table / status badges) ---

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiBold   = "\033[1m"
	ansiCyan   = "\033[36m"
)

func badge(sev rules.Severity) string {
	switch sev {
	case rules.SeverityCritical:
		return ansiRed + ansiBold + "[CRITICAL]" + ansiReset
	case rules.SeverityWarning:
		return ansiYellow + ansiBold + "[WARNING] " + ansiReset
	default:
		return ansiCyan + "[INFO]    " + ansiReset
	}
}

func renderText(r ScanReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s git-smells-wrong scan %s%s\n", ansiBold, r.Target, ansiReset)
	fmt.Fprintf(&sb, "Branch: %s   Time: %s\n\n", r.Branch, r.Timestamp.Format(time.RFC3339))
	if len(r.Findings) == 0 {
		fmt.Fprintf(&sb, "%s No malicious or high-risk patterns found. Verdict: CLEAN.%s\n", ansiGreen+ansiBold+"[CLEAN]"+ansiReset, "")
	} else {
		fmt.Fprintf(&sb, "%-12s %-10s %-28s %s\n", "SEVERITY", "RULE", "FILE", "TITLE")
		fmt.Fprintf(&sb, "%s\n", strings.Repeat("-", 80))
		for _, f := range r.Findings {
			fmt.Fprintf(&sb, "%s %-10s %-28s %s\n", badge(f.Severity), f.RuleID, trunc(f.File, 28), f.Title)
			fmt.Fprintf(&sb, "  %s\n", wrapLine(f.Description, 78))
			if f.Snippet != "" {
				fmt.Fprintf(&sb, "  %s> %s%s\n", ansiCyan, truncOneLine(f.Snippet, 120), ansiReset)
			}
		}
		fmt.Fprintln(&sb)
	}
	if len(r.Trace.NetworkIndicators) > 0 {
		fmt.Fprintf(&sb, "Network indicators (dry-run, not executed):\n")
		for _, n := range r.Trace.NetworkIndicators {
			fmt.Fprintf(&sb, "  - %s\n", n)
		}
		fmt.Fprintln(&sb)
	}
	verdictColor := ansiGreen
	if r.Summary.ExitCode == ExitCritical {
		verdictColor = ansiRed
	} else if r.Summary.ExitCode == ExitWarning {
		verdictColor = ansiYellow
	}
	fmt.Fprintf(&sb, "Summary: %d critical, %d warning, %d info  →  %s%s%s%s (exit %d)\n",
		r.Summary.Critical, r.Summary.Warning, r.Summary.Info,
		verdictColor+ansiBold, r.Summary.Verdict, ansiReset, "", r.Summary.ExitCode)
	return sb.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func truncOneLine(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	return trunc(s, n)
}

func wrapLine(s string, width int) string {
	if len(s) <= width {
		return s
	}
	// Simple hard wrap.
	var out strings.Builder
	for len(s) > width {
		out.WriteString(s[:width])
		out.WriteString("\n  ")
		s = s[width:]
	}
	out.WriteString(s)
	return out.String()
}

// --- SARIF 2.1.0 ---

func renderSARIF(r ScanReport) (string, error) {
	level := func(s rules.Severity) string {
		switch s {
		case rules.SeverityCritical:
			return "error"
		case rules.SeverityWarning:
			return "warning"
		default:
			return "note"
		}
	}
	type sarifRule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name": "git-smells-wrong",
						"rules": []sarifRule{
							{ID: "HOOK-001", Name: "GitHooks"},
							{ID: "NPM-002", Name: "NpmLifecycle"},
							{ID: "PY-003", Name: "PythonBuild"},
							{ID: "IDE-004", Name: "IdeAutoRun"},
						},
					},
				},
				"results": func() []sarifResult {
					var res []sarifResult
					for _, f := range r.Findings {
						var sr sarifResult
						sr.RuleID = f.RuleID
						sr.Level = level(f.Severity)
						sr.Message.Text = f.Title + ": " + f.Description
						loc := struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
							} `json:"physicalLocation"`
						}{}
						loc.PhysicalLocation.ArtifactLocation.URI = f.File
						sr.Locations = []struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
							} `json:"physicalLocation"`
						}{loc}
						res = append(res, sr)
					}
					if res == nil {
						res = []sarifResult{}
					}
					return res
				}(),
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}
