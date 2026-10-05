# Product Requirement Document (PRD)

## Project Overview

* **Project Name:** `git-guard` (CLI & Containerized Git Sandbox & Malicious Repo Auditor)
* **Language & Runtime:** Go (Golang)
* **Target Audience:** Backend engineers, security researchers, and developers reviewing take-home interview assignments, open-source repositories, or untrusted code archives.
* **Core Value Proposition:** A dual-distribution security auditor available as either a native standalone Go CLI binary or a zero-dependency Docker image. Both distributions safely clone, inspect, and analyze untrusted repositories for malicious delivery vectors (`.git/hooks/`, package lifecycle hooks, IDE auto-run tasks, and dangerous system calls) without exposing the host environment.

---

## 1. Problem Statement

Developer-targeted supply-chain attacks (notably "Contagious Interview" campaigns by Lazarus Group / DPRK actors) target engineers via fake take-home assignments. Malicious payloads are embedded inside:

* Pre-configured Git hooks (`.git/hooks/post-checkout`, `pre-commit`)


* Package manager lifecycle scripts (`package.json` `preinstall`/`postinstall`, `setup.py`)
* IDE workspace triggers (`.vscode/tasks.json` with `runOn: folderOpen`)

When an engineer clones or tests the code, these hooks execute automatically in the background, exfiltrating credentials (`~/.ssh`, `~/.aws`, browser tokens) or establishing reverse shells. A unified Go tool is needed that can run either natively on the host or inside a hardened container to inspect and trace these projects safely.

---

## 2. Product Goals & Non-Goals

### Goals

* **Dual Execution Modes:**
* **Mode 1: Standalone Host CLI Binary:** A single Go binary that users can install (`go install` or download precompiled) to scan repos directly. When Docker is present on the host, the CLI can optionally delegate execution into an isolated container.
* **Mode 2: Self-Contained Docker Image:** A minimal, hardened container image containing the Go binary, ready to run via `docker run --rm ghcr.io/.../git-guard <repo-url>` with zero host setup.


* **Dual-Stage Inspection Engine:**
* **Stage 1 (Static):** Fast, zero-execution inspection of `.git/hooks/`, manifests (`package.json`, `setup.py`), and IDE configuration files.
* **Stage 2 (Dynamic - Optional/Isolated):** Monitored dry-run execution (e.g., simulating `git checkout` or manifest parsing) in a contained environment while logging child process spawns and outbound network calls.


* **Zero Host Contamination:** The ingestion phase must suppress template hooks (`--template=/dev/null`) and protect against directory traversal (Zip-Slip).
* **Multiple Output Formats:** Human-readable terminal output (colored tables/status badges) and machine-readable JSON/SARIF.

### Non-Goals

* Deep static application security testing (SAST) for source-code business logic or algorithmic flaws.
* Traditional signature-based antivirus replacement (e.g., ClamAV/VirusTotal hash lookups).

---

## 3. Architecture & Distribution Matrix

```
                      +---------------------------------------+
                      |         Target Distribution           |
                      +---------------------------------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
    [Native Go CLI Binary]                      [Official Docker Image]
    • Built via `go build`                      • Multi-stage build (Alpine/Scratch)
    • Runs directly on host                     • Ships with Go binary + git
    • Inspects local folders/archives           • Runs completely isolated in
      or clones to temporary dir                  container namespace
    • Optional: auto-delegates to               • Compatible with gVisor (`runsc`)
      `runsc` if `--sandbox=docker` is set
                               |                           |
                               +-------------+-------------+
                                             |
                                             v
                           +-----------------------------------+
                           |      Shared Go Core Engine        |
                           |  - Ingestion (Safe clone/unzip)   |
                           |  - Static Rule Matchers           |
                           |  - Process & Egress Monitor       |
                           |  - Formatter (CLI Table / JSON)   |
                           +-----------------------------------+

```

---

## 4. User Experience & CLI Specification

Both the standalone CLI binary and the Docker image share identical flag conventions and arguments.

### 4.1 Invocation Commands

#### Standalone Host CLI:

```bash
# Scan a remote Git repository
git-guard scan --repo="https://github.com/evil-org/test-task.git"

# Scan a local zipped take-home test
git-guard scan --archive="./take-home.zip"

# Scan and export JSON report
git-guard scan --repo="https://github.com/evil-org/test-task.git" --report="./report.json" --format=json

# Force isolated execution via Docker/gVisor from the CLI binary
git-guard scan --repo="https://github.com/evil-org/test-task.git" --sandbox=docker

```

#### Docker Image:

```bash
# Direct scan printing to STDOUT
docker run --rm ghcr.io/yourorg/git-guard:latest \
  scan --repo="https://github.com/evil-org/test-task.git"

# Scan and persist JSON report to host volume
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  ghcr.io/yourorg/git-guard:latest \
  scan --repo="https://github.com/evil-org/test-task.git" \
       --report="/reports/scan-result.json" \
       --format=json

```

### 4.2 Global CLI Flags

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--repo` | `string` | `""` | URL of the remote Git repository to clone and inspect. |
| `--archive` | `string` | `""` | Path to a local `.zip` or `.tar.gz` archive. |
| `--branch` | `string` | `"HEAD"` | Specific branch/tag to checkout during dynamic trace. |
| `--report` | `string` | `""` | File path to write the output report (if empty, prints to STDOUT). |
| `--format` | `string` | `"text"` | Output format: `text` (terminal UI), `json`, or `sarif`. |
| `--sandbox` | `string` | `"native"` | Execution backend: `native` (in-process) or `docker` (spawns container). |
| `--timeout` | `duration` | `2m` | Execution timeout for clone and analysis phases. |

---

## 5. Technical Specification & Implementation

### 5.1 Project Directory Structure

```
git-guard/
├── cmd/
│   └── git-guard/
│       └── main.go              # Cobra CLI entrypoint
├── internal/
│   ├── config/                  # CLI flags and runtime config
│   ├── engine/                  # Scan orchestrator
│   ├── ingestion/               # Safe Git clone and Zip-Slip-safe extractor
│   ├── rules/                   # Static detection rules (hooks, npm, vscode)
│   ├── tracer/                  # Dynamic execution monitor (proc/net)
│   ├── sandbox/                 # Docker/gVisor client integration
│   └── report/                  # Table and JSON report generators
├── Dockerfile                   # Multi-stage production container build
├── Makefile                     # Build targets (binaries, docker image)
├── go.mod
└── go.sum

```

### 5.2 Key Functional Components

#### A. Ingestion Engine (`internal/ingestion`)

* **Remote Git Clones:** Must pass `--template=/dev/null` to prevent copying global or system-level hook templates into the target working directory.
* **Archive Extraction:** For `.zip` and `.tar.gz`, implement strict path validation against `filepath.Clean` and check for `..` prefixing to block Zip-Slip attacks before writing any file to `/tmp`.

#### B. Static Rules Engine (`internal/rules`)

* **Rule `HOOK-001` (Git Hooks):**

* Target: `.git/hooks/*` (ignore `.sample` files).


* Check: Detect non-standard executable scripts containing shell invocations (`sh`, `bash`), outbound utilities (`curl`, `wget`, `nc`), network redirections (`/dev/tcp/`), or base64 blobs.




* **Rule `NPM-002` (Package Manifests):**
* Target: `package.json`.
* Check: Parse `scripts` for automatic lifecycle entries (`preinstall`, `install`, `postinstall`, `prepack`).


* **Rule `PY-003` (Python Builds):**
* Target: `setup.py`, `setup.cfg`.
* Check: Detect executable logic outside declarative metadata or custom `cmdclass` hooks.


* **Rule `IDE-004` (IDE Configurations):**
* Target: `.vscode/tasks.json`.
* Check: Look for tasks configured with `"runOn": "folderOpen"`.



#### C. Report & Exit Codes

* **Exit Code `0`:** Clean (No malicious or high-risk patterns found).
* **Exit Code `1`:** Warning / High risk (Unpinned install hooks, suspicious workspace settings).
* **Exit Code `2`:** Critical / Fail (Active malicious git hooks, outbound reverse shell patterns detected).



---

## 6. Docker Build Pipeline

The project uses a unified multi-stage `Dockerfile` to produce a minimal, non-root runtime container.

```dockerfile
# Stage 1: Build the Go binary
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-w -s" \
    -o /out/git-guard ./cmd/git-guard

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache git bash ca-certificates jq \
    && adduser -D -u 10001 appuser

USER 10001
WORKDIR /home/appuser

COPY --from=builder /out/git-guard /usr/local/bin/git-guard

ENTRYPOINT ["git-guard"]
CMD ["--help"]

```

---

## 7. Phased Implementation Roadmap

* **Phase 1: Shared Core & CLI (Week 1)**
* Scaffold CLI flags with `spf13/cobra`.
* Implement safe clone (`--template=/dev/null`) and Zip-Slip validation.
* Implement static checks for `.git/hooks/*`, `package.json`, and `.vscode/tasks.json`.


* Build formatted CLI table output and raw JSON output.


* **Phase 2: Docker Release & Sandboxing (Week 2)**
* Finalize multi-stage `Dockerfile` and automated GitHub Actions build/push to GHCR.
* Integrate Docker Go SDK (`[github.com/docker/docker/client](https://github.com/docker/docker/client)`) into the native CLI binary so passing `--sandbox=docker` automatically spins up the `git-guard` container using gVisor (`runsc`).


* **Phase 3: Dynamic Tracing (Week 3)**
* Implement process tree auditing inside the container to trace child binaries spawned when running `git checkout` or build tasks.


* Log outbound socket connections and DNS resolution attempts to catch C2 callbacks.
