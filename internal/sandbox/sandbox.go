package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// Image is the official container image used for sandboxed delegation.
const Image = "dattm24/git-smells-wrong:latest"

// IsDockerAvailable reports whether the docker CLI is on PATH.
func IsDockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// DelegateToDocker re-executes the equivalent `scan` inside the official
// image via `docker run --rm`, forwarding report output. It maps the host
// --report path (if any) into /reports in the container so results persist.
// args are the original scan flags (excluding program name), rewritten so
// the in-container invocation uses --sandbox=native.
func DelegateToDocker(args []string, reportHostPath string) int {
	if !IsDockerAvailable() {
		fmt.Fprintln(os.Stderr, "git-smells-wrong: docker CLI not found on PATH; cannot use --sandbox=docker")
		return 2
	}
	rewritten := rewriteSandbox(args)
	dockerArgs := []string{"run", "--rm", "--network", "none"}
	if reportHostPath != "" {
		// Mount the report's parent dir at /reports and rewrite --report.
		rewritten = rewriteReport(rewritten, "/reports/report.out")
		dockerArgs = append(dockerArgs, "-v", reportDir(reportHostPath)+":/reports")
	}
	dockerArgs = append(dockerArgs, Image)
	dockerArgs = append(dockerArgs, append([]string{"scan"}, rewritten...)...)

	cmd := exec.Command("docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "git-smells-wrong: docker run failed: %v\n", err)
		return 2
	}
	return 0
}

func rewriteSandbox(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--sandbox=docker" {
			out = append(out, "--sandbox=native")
			continue
		}
		if a == "--sandbox" && i+1 < len(args) {
			out = append(out, "--sandbox", "native")
			i++
			continue
		}
		out = append(out, a)
	}
	return out
}

func rewriteReport(args []string, newVal string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 9 && a[:9] == "--report=" {
			out = append(out, "--report="+newVal)
			continue
		}
		if a == "--report" && i+1 < len(args) {
			out = append(out, "--report", newVal)
			i++
			continue
		}
		out = append(out, a)
	}
	return out
}

func reportDir(p string) string {
	if i := lastSlash(p); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func lastSlash(p string) int {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return i
		}
	}
	return -1
}
