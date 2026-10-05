# ⚠️ BENIGN SECURITY DEMO — NOT REAL MALWARE ⚠️

Inert test fixture for git-smells-wrong, mimicking a "Contagious
Interview" style malicious take-home assignment.

**Every payload is deliberately harmless:** network targets use
reserved, non-routable addresses (`192.0.2.10` is RFC 5737 TEST-NET-1,
`demo.test` is RFC 2606 reserved) and the base64 blob decodes to
`harmless-demo-fixture`. Nothing can be reached or exfiltrated.

Vectors (one per detection rule):

| # | Vector | Path in this archive |
|---|--------|----------------------|
| 1 | Git hook auto-execution | `.git/hooks/post-checkout` |
| 2 | npm `postinstall` hook | `package.json` |
| 3 | Python install-time `cmdclass` | `setup.py` |
| 4 | VS Code `folderOpen` task | `.vscode/tasks.json` |

## The (fake) assignment

> **Frontend Take-Home — Acme Corp hiring challenge**
>
> Build a todo app in `index.js`. Run `npm install` to set up, then
> open the folder in VS Code. Good luck! 🚩
