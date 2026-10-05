# Demo: evil-take-home.zip

An **inert** malicious take-home archive for trying git-smells-wrong.
All payloads are harmless by construction (unroutable TEST-NET-1
addresses, reserved `.test` domains, a base64 blob that decodes to
`harmless-demo-fixture`).

## Play with it

```bash
# Regenerate the archive (checked in, but rebuildable)
./demo/make-evil-zip.sh

# Scan it — expect 4 CRITICAL findings, exit 2
git-smells-wrong scan --archive=./demo/evil-take-home.zip
```

Expected verdict: `HOOK-001` (git hook with curl + `/dev/tcp` +
base64 stager), `NPM-002` (`postinstall` pipe), `PY-003`
(`cmdclass` + `os.system`), `IDE-004` (`folderOpen` task).

## Watching the payloads (safely)

Cloning a repo never installs `.git/hooks` — that vector only travels
inside archives like this one. To see the payloads attempt (and fail):

```bash
timeout 10 bash -c 'unzip -p demo/evil-take-home.zip .git/hooks/post-checkout | bash -x /dev/stdin'
# stage 1 curls an unroutable IP (hangs, killed by timeout),
# stage 2 reverse-shell dial would hang the same way,
# stage 3 decodes to "harmless-demo-fixture". Nothing leaves the machine.
```

## Layout

- `evil-take-home.zip` — the ready-made demo archive
- `make-evil-zip.sh` — regenerates it from `src/`
- `src/` — payload sources; `src/hooks/` is staged into
  `.git/hooks/` at build time (git can't track a `.git/` dir,
  which is also why this vector needs an archive, not a repo)
