package tracer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// TraceEvent describes something that WOULD execute during a normal
// checkout/install/open cycle. git-smells-wrong intentionally never executes
// untrusted hooks or lifecycle scripts in native mode; the tracer performs
// a dry-run enumeration plus indicator extraction (URLs, IPs, DNS names).
type TraceEvent struct {
	Kind   string `json:"kind"`   // "git-hook" | "npm-hook" | "ide-task" | "python-install"
	Detail string `json:"detail"` // human-readable description
}

type TraceResult struct {
	Events            []TraceEvent `json:"events"`
	NetworkIndicators []string     `json:"network_indicators"`
	Note              string       `json:"note"`
}

var (
	reURL = regexp.MustCompile(`https?://[^\s"'<>]+`)
	reIP  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
)

// DryRun enumerates auto-execution vectors without running them and extracts
// network indicators from their contents.
func DryRun(workDir string) TraceResult {
	res := TraceResult{
		Note: "Dry-run only: no untrusted hooks, scripts, or tasks were executed. Run with --sandbox=docker for isolated dynamic tracing.",
	}
	seen := map[string]bool{}
	addNet := func(content string) {
		for _, m := range reURL.FindAllString(content, -1) {
			m = strings.TrimRight(m, ".,;)")
			if !seen[m] {
				seen[m] = true
				res.NetworkIndicators = append(res.NetworkIndicators, m)
			}
		}
		for _, m := range reIP.FindAllString(content, -1) {
			if !seen[m] {
				seen[m] = true
				res.NetworkIndicators = append(res.NetworkIndicators, m)
			}
		}
	}

	// Git hooks that git would execute on checkout/commit/etc.
	hooksDir := filepath.Join(workDir, ".git", "hooks")
	if entries, err := os.ReadDir(hooksDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
				continue
			}
			res.Events = append(res.Events, TraceEvent{
				Kind:   "git-hook",
				Detail: ".git/hooks/" + e.Name() + " would execute on the corresponding git operation (e.g. post-checkout, pre-commit)",
			})
			if data, err := readHead(filepath.Join(hooksDir, e.Name())); err == nil {
				addNet(data)
			}
		}
	}
	// package.json / setup.py / tasks.json contents for indicators.
	for _, rel := range []string{"package.json", "setup.py", "setup.cfg", ".vscode/tasks.json"} {
		if data, err := readHead(filepath.Join(workDir, rel)); err == nil {
			addNet(data)
		}
	}
	if res.Events == nil {
		res.Events = []TraceEvent{}
	}
	if res.NetworkIndicators == nil {
		res.NetworkIndicators = []string{}
	}
	return res
}

func readHead(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var sb strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
		if sb.Len() > 1<<20 {
			break
		}
	}
	return sb.String(), nil
}
