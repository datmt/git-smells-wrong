package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Severity levels. Mapping to exit codes is done in the report package:
// critical -> 2, warning -> 1, clean (no findings) -> 0.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// Finding is a single rule match.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	File        string   `json:"file"`
	Description string   `json:"description"`
	Snippet     string   `json:"snippet,omitempty"`
}

// --- Shared suspicious-pattern matchers ---

var (
	// Network / exfiltration / reverse-shell indicators.
	reOutbound = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|netcat|socat|telnet|ftp|scp)\b|/dev/tcp/|/dev/udp/|__import__\s*\(\s*["']socket["']|reverse\s*shell|/bin/(ba)?sh\s+-i\b|bash\s+-i\b|powershell|cmd\.exe|mshta|certutil|bitsadmin`)
	reB64Blob  = regexp.MustCompile(`(?i)\b(base64\s+(-d|--decode)|\bbase64\b.{0,40}decode|powershell\s+(-e(nc|ncodedcommand)?)\b|echo\s+[A-Za-z0-9+/=]{80,})`)
	reShell    = regexp.MustCompile(`(?i)\b(sh|bash|zsh|dash)\b|#!/.*\b(bash|sh)\b`)
	reProcExec = regexp.MustCompile(`(?i)\b(os\.system|os\.popen|os\.exec|os\.spawn|subprocess\.(Popen|call|run)|popen|system\s*\(|eval\s*\(|exec\s*\()`)
	reExfil    = regexp.MustCompile(`(?i)(\.ssh|\.aws|browser|token|credential|passwd|shadow|id_rsa|\.gnupg|cookie)`)
)

// suspiciousScore classifies content: 2 = actively malicious, 1 = shell-ish, 0 = benign.
func suspiciousScore(content string) int {
	if reOutbound.MatchString(content) || reB64Blob.MatchString(content) {
		return 2
	}
	if reProcExec.MatchString(content) || reExfil.MatchString(content) {
		return 2
	}
	if reShell.MatchString(content) {
		return 1
	}
	return 0
}

func relPath(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return abs
	}
	return filepath.ToSlash(rel)
}

func readFileCapped(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	return string(buf[:n]), nil
}

func snippetOf(content string) string {
	content = strings.TrimSpace(content)
	// Lead with the actual evidence: up to 3 suspicious lines, wherever
	// they sit in the file. Falling back to the file head is what makes
	// reports read as fabricated (boilerplate instead of payload).
	matches := func(l string) bool {
		return reOutbound.MatchString(l) || reB64Blob.MatchString(l) || reProcExec.MatchString(l)
	}
	collect := func(skipComments bool) []string {
		var hits []string
		for _, l := range strings.Split(content, "\n") {
			t := strings.TrimSpace(l)
			if t == "" {
				continue
			}
			if skipComments && strings.HasPrefix(t, "#") {
				continue
			}
			if matches(l) {
				hits = append(hits, t)
				if len(hits) == 3 {
					break
				}
			}
		}
		return hits
	}
	// Prefer code lines as evidence; comments mentioning payloads
	// ("fake reverse shell") are only used when nothing else matched.
	hits := collect(true)
	if len(hits) == 0 {
		hits = collect(false)
	}
	if len(hits) > 0 {
		s := strings.Join(hits, " / ")
		if len(s) > 300 {
			return s[:300] + "…"
		}
		return s
	}
	// No suspicious lines: first non-comment, non-empty line.
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if len(t) > 300 {
			return t[:300] + "…"
		}
		return t
	}
	return ""
}

// ScanAll runs every static rule over workDir.
func ScanAll(workDir string) ([]Finding, error) {
	var out []Finding
	scanners := []func(string) ([]Finding, error){
		ScanGitHooks,
		ScanNPM,
		ScanPython,
		ScanIDE,
	}
	for _, s := range scanners {
		f, err := s(workDir)
		if err != nil {
			return nil, err
		}
		out = append(out, f...)
	}
	return out, nil
}

// --- Rule HOOK-001: Git hooks ---

// ScanGitHooks inspects .git/hooks/* (ignoring *.sample).
func ScanGitHooks(workDir string) ([]Finding, error) {
	hooksDir := filepath.Join(workDir, ".git", "hooks")
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read .git/hooks: %w", err)
	}
	var findings []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".sample") {
			continue
		}
		abs := filepath.Join(hooksDir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		content, err := readFileCapped(abs, 1<<20)
		if err != nil {
			continue
		}
		executable := info.Mode()&0o111 != 0
		hasShebang := strings.HasPrefix(content, "#!")
		if !executable && !hasShebang && strings.TrimSpace(content) == "" {
			continue
		}
		rel := relPath(workDir, abs)
		score := suspiciousScore(content)
		switch {
		case score >= 2:
			findings = append(findings, Finding{
				RuleID:      "HOOK-001",
				Severity:    SeverityCritical,
				Title:       "Malicious git hook",
				File:        rel,
				Description: "Executable git hook contains outbound-execution or reverse-shell indicators (curl/wget/nc, /dev/tcp, base64 blob, process execution). It runs automatically on clone/checkout/commit.",
				Snippet:     snippetOf(content),
			})
		case score == 1 || executable || hasShebang:
			findings = append(findings, Finding{
				RuleID:      "HOOK-001",
				Severity:    SeverityWarning,
				Title:       "Custom git hook present",
				File:        rel,
				Description: "Non-sample executable git hook found. Hooks execute automatically on git operations; review before running git commands.",
				Snippet:     snippetOf(content),
			})
		}
	}
	return findings, nil
}

// --- Rule NPM-002: package.json lifecycle scripts ---

var npmAutoHooks = []string{"preinstall", "install", "postinstall", "prepack", "prepublish", "prepublishOnly", "postpack"}

func ScanNPM(workDir string) ([]Finding, error) {
	path := filepath.Join(workDir, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return []Finding{{
			RuleID:      "NPM-002",
			Severity:    SeverityWarning,
			Title:       "Unparseable package.json",
			File:        "package.json",
			Description: "package.json could not be parsed; lifecycle hooks cannot be verified. Inspect manually.",
		}}, nil
	}
	var findings []Finding
	for _, hook := range npmAutoHooks {
		script, ok := manifest.Scripts[hook]
		if !ok {
			continue
		}
		if suspiciousScore(script) >= 2 {
			findings = append(findings, Finding{
				RuleID:      "NPM-002",
				Severity:    SeverityCritical,
				Title:       "Malicious npm lifecycle hook",
				File:        "package.json",
				Description: fmt.Sprintf("Automatic lifecycle script %q contains outbound-execution indicators. It runs on npm install without further prompting.", hook),
				Snippet:     fmt.Sprintf("%s: %s", hook, script),
			})
		} else {
			findings = append(findings, Finding{
				RuleID:      "NPM-002",
				Severity:    SeverityWarning,
				Title:       "Automatic npm lifecycle hook",
				File:        "package.json",
				Description: fmt.Sprintf("Automatic lifecycle script %q is defined and runs on npm install. Review its contents before installing.", hook),
				Snippet:     fmt.Sprintf("%s: %s", hook, script),
			})
		}
	}
	return findings, nil
}

// --- Rule PY-003: setup.py / setup.cfg ---

var pySuspicious = regexp.MustCompile(`(?i)(cmdclass|setuptools\.command|distutils|os\.system|os\.popen|subprocess|socket|urllib|requests\.get|eval\s*\(|exec\s*\(|__import__|install\.run|easy_install)`)

func ScanPython(workDir string) ([]Finding, error) {
	var findings []Finding
	setupPy := filepath.Join(workDir, "setup.py")
	if data, err := os.ReadFile(setupPy); err == nil {
		content := string(data)
		switch {
		case suspiciousScore(content) >= 2 || pySuspicious.MatchString(content):
			sev := SeverityWarning
			title := "Suspicious setup.py logic"
			desc := "setup.py contains executable logic beyond declarative metadata (cmdclass, subprocess/os execution, or network imports). It executes at install time via `pip install`."
			if suspiciousScore(content) >= 2 {
				sev = SeverityCritical
				title = "Malicious setup.py logic"
				desc = "setup.py contains outbound-execution or reverse-shell indicators and runs at install time. Do not `pip install` this project on the host."
			}
			findings = append(findings, Finding{
				RuleID: "PY-003", Severity: sev, Title: title,
				File: "setup.py", Description: desc, Snippet: snippetOf(content),
			})
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read setup.py: %w", err)
	}

	setupCfg := filepath.Join(workDir, "setup.cfg")
	if data, err := os.ReadFile(setupCfg); err == nil {
		content := string(data)
		if suspiciousScore(content) >= 2 {
			findings = append(findings, Finding{
				RuleID: "PY-003", Severity: SeverityCritical, Title: "Malicious setup.cfg content",
				File: "setup.cfg", Description: "setup.cfg contains outbound-execution indicators. setup.cfg is normally declarative; treat embedded commands as malicious.", Snippet: snippetOf(content),
			})
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read setup.cfg: %w", err)
	}
	return findings, nil
}

// --- Rule IDE-004: .vscode/tasks.json runOn folderOpen ---

type vscodeTasks struct {
	Tasks []map[string]any `json:"tasks"`
}

func ScanIDE(workDir string) ([]Finding, error) {
	path := filepath.Join(workDir, ".vscode", "tasks.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read .vscode/tasks.json: %w", err)
	}
	var parsed vscodeTasks
	if err := json.Unmarshal(data, &parsed); err != nil {
		return []Finding{{
			RuleID:      "IDE-004",
			Severity:    SeverityWarning,
			Title:       "Unparseable .vscode/tasks.json",
			File:        ".vscode/tasks.json",
			Description: "tasks.json could not be parsed; auto-run tasks cannot be verified. Inspect manually.",
		}}, nil
	}
	var findings []Finding
	raw := string(data)
	for _, t := range parsed.Tasks {
		runOn, _ := t["runOn"].(string)
		if !strings.EqualFold(runOn, "folderOpen") {
			continue
		}
		label, _ := t["label"].(string)
		if label == "" {
			label, _ = t["taskName"].(string)
		}
		blob, _ := json.Marshal(t)
		sev := SeverityWarning
		title := "IDE auto-run task (folderOpen)"
		desc := "VS Code task is configured with \"runOn\": \"folderOpen\" and executes automatically when the folder is opened."
		if suspiciousScore(string(blob)) >= 2 || suspiciousScore(raw) >= 2 && suspiciousScore(string(blob)) >= 1 {
			sev = SeverityCritical
			title = "Malicious IDE auto-run task"
			desc = "VS Code folderOpen task contains outbound-execution indicators and runs automatically on folder open."
		}
		findings = append(findings, Finding{
			RuleID: "IDE-004", Severity: sev, Title: title,
			File:        ".vscode/tasks.json",
			Description: desc + " Task: " + label,
			Snippet:     snippetOf(string(blob)),
		})
	}
	return findings, nil
}
