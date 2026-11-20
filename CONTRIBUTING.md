# Contributing

Thank you for helping improve Codex-HackerOne-Investigator. Contributions must preserve
the project's default-deny model and remain safe to review and run offline.

## Development setup

Requirements:

- Python 3.11 or newer;
- Bash and GNU core utilities; and
- Git for normal contribution workflows.

Clone or extract the repository, then run the project directly from the checkout:

```bash
cd Codex-HackerOne-Investigator
export PYTHONPATH="$PWD/src"
python3 -m unittest discover -s tests -v
```

The runtime and test suite use the Python standard library. Do not add a dependency
without explaining its security, maintenance, licensing, and offline-install impact.

## Required checks

Before opening a pull request, run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
bash -n scripts/install.sh
python3 scripts/audit-release.py .
sha256sum -c RELEASE-MANIFEST.sha256
```

Also parse every Python file without creating bytecode:

```bash
python3 - <<'PY'
import ast
from pathlib import Path

paths = sorted(Path("src").rglob("*.py"))
paths += sorted(Path("scripts").glob("*.py"))
paths += sorted(Path("tests").glob("*.py"))
for path in paths:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
print(f"Parsed {len(paths)} Python files")
PY
```

If an approved distribution file changes, regenerate
`RELEASE-MANIFEST.sha256` as the final file operation:

```bash
find . -type f ! -path './.git/*' \
  ! -name RELEASE-MANIFEST.sha256 -print0 \
  | sort -z | xargs -0 sha256sum > RELEASE-MANIFEST.sha256
sha256sum -c RELEASE-MANIFEST.sha256
```

## Security rules

- Never commit credentials, tokens, cookies, private keys, secret-file contents, or
  authentication headers.
- Never commit private HackerOne snapshots, program data, evidence, reports, target
  identifiers, personal information, or live allowlists.
- Use reserved example domains, documentation IP ranges, and obviously synthetic
  fixtures in tests and documentation.
- Keep public configurations disabled with empty target lists.
- Do not add automatic scanning, live requests, redirects, retries, deployment,
  service activation, firewall changes, or STOP removal to tests or installation.
- Preserve exact-host and exact-URL enforcement, TLS checks, public-IP pinning,
  request limits, approval metadata, and fail-closed behavior.
- Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md), not in a
  public issue.

## Code and test guidance

- Prefer small, reviewable changes with explicit failure behavior.
- Add negative tests for every new security boundary.
- Tests must run offline and must not depend on credentials, DNS, or external services.
- Keep raw response bodies and secrets out of logs. Prefer redacted metadata.
- Document assumptions, limitations, and any change to the threat model.
- Maintain compatibility with the minimum supported Python version.

## Documentation guidance

Commands must match the actual command-line interface. Clearly label examples as
offline, local, or potentially network-active. Do not imply that this project grants
authorization or provides complete isolation. Link to the canonical safety and
architecture documents instead of duplicating controls inconsistently.

## Pull-request checklist

A pull request should:

1. explain the problem, approach, and security impact;
2. identify affected stages and threat-model assumptions;
3. include or update offline tests;
4. pass all required checks;
5. contain no secrets or private investigation material;
6. update documentation and the release manifest when needed; and
7. avoid unrelated formatting or generated-file changes.

Maintainers may request a smaller patch, additional negative tests, or a private
security report before reviewing security-sensitive behavior.
