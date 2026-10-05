#!/usr/bin/env bash
# Build the inert evil-take-home demo archive.
# Usage: ./demo/make-evil-zip.sh [output]   (default: demo/evil-take-home.zip)
#
# Layout trick: git cannot track a `.git/` directory, so the hook source
# lives at demo/src/hooks/ and is staged into `.git/hooks/` here — the
# same path it occupies in real malicious archives.
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-./evil-take-home.zip}"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/.git/hooks" "$STAGE/.vscode"
cp src/README.md src/package.json src/setup.py src/index.js "$STAGE/"
cp src/.vscode/tasks.json "$STAGE/.vscode/"
cp src/hooks/post-checkout "$STAGE/.git/hooks/"

python3 - "$STAGE" "$OUT" <<'EOF'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
if os.path.exists(out):
    os.remove(out)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(stage):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, stage)
            zi = zipfile.ZipInfo(arc)
            # Preserve the executable bit: git silently skips hooks that
            # are not +x, and Python's zipfile does not store modes by
            # default. Real lures use tar.gz or set this for a reason.
            with open(full, "rb") as fh:
                data = fh.read()
            if arc == ".git/hooks/post-checkout":
                zi.external_attr = (0o755 << 16)
            else:
                zi.external_attr = (0o644 << 16)
            z.writestr(zi, data)
print(f"wrote {out}")
EOF
