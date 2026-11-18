# Known image vulnerabilities

Inspector findings on the secure-mcp-gateway image that stay open on purpose. Nothing here is suppressed in Inspector.
Full reasoning, the alternatives tested and when to revisit are in apiaas `docs/security/known-vulnerabilities.md`.

## python-pip / python3-pip-whl 24.0+dfsg-1ubuntu1.3: CVE-2025-66418, CVE-2025-66471

- **Why not fixed.** Ubuntu ships the fix only in Ubuntu Pro (ESM). `python3-pip-whl` can't be removed, because
  `python3.12-venv` depends on it and MCP servers create virtualenvs.
- **Why not exploitable here.** The Dockerfile replaces the pip wheel inside the package with a current pip, and a
  `python3 -m venv` probe fails the build if that stops working. Inspector reads only the dpkg version, so it still
  reports the package.
- **Alternatives tested 2026-11-17, not adopted:**
  - `python:3.12-slim-trixie` as the base. It matches on every tool and test, but brings Debian's unfixable git and krb5
    findings (a net increase), plus a second `/usr/bin/python3` (Debian 3.13).
  - A stub `.deb` that claims the package. That hides the finding rather than fixing it.
- **Revisit when** Ubuntu publishes the fix outside ESM, or if we adopt Ubuntu Pro.
