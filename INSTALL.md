# Debian and Linux installation guide

This guide covers a safe installation from a GitHub ZIP archive or source checkout.
Installation copies code and disabled templates. It does not create a live target
configuration, install a systemd unit, remove the emergency STOP file, start the
request broker, alter firewall rules, or run network tests.

## 1. Supported baseline

- Debian 12 or newer, Ubuntu 22.04 or newer, or a comparable Linux distribution.
- Python 3.11 or newer.
- Bash, GNU core utilities, and CA certificates.
- `unzip` for ZIP archives.
- Root access only for the optional system-wide installation.

The application uses the Python standard library at runtime. Development and offline
testing do not require downloading Python packages.

## 2. Download a ZIP archive

Download the source archive from the repository's
[Releases page](https://github.com/CaptnCrypto/Codex-HackerOne-Investigator/releases)
or use GitHub's **Code → Download ZIP** option.

Assuming the archive is in `~/Downloads`:

```sh
mkdir -p "$HOME/src"
cd "$HOME/src"
unzip "$HOME/Downloads/Codex-HackerOne-Investigator-0.1.0.zip"
cd Codex-HackerOne-Investigator-0.1.0
```

GitHub may use a different extracted directory name for a branch archive. Enter the
directory that contains `README.md`, `scripts/`, `src/`, and `tests/`.

Alternatively, clone the repository:

```sh
git clone https://github.com/CaptnCrypto/Codex-HackerOne-Investigator.git
cd Codex-HackerOne-Investigator
```

Do not place the checkout inside a private investigation case or credential directory.

## 3. Install prerequisites on Debian or Ubuntu

```sh
sudo apt update
sudo apt install --yes python3 ca-certificates unzip
```

For a Git checkout, also install Git:

```sh
sudo apt install --yes git
```

Verify the interpreter:

```sh
python3 --version
```

Python 3.11 or newer is required.

## 4. Verify the downloaded tree

From the repository root:

```sh
sha256sum -c RELEASE-MANIFEST.sha256
python3 scripts/audit-release.py .
```

The manifest covers every distributed file except the manifest itself. The release
audit checks for unexpected binary files, symlinks, common secret patterns, private
case markers, unfinished Stage 5 runtime files, and enabled public configurations.

If verification fails, stop. Re-download from the official repository and investigate
the mismatch before running any script as root.

## 5. Run the offline tests

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
```

The tests use synthetic fixtures and monkeypatch network connection entry points. They
must pass without API credentials, live targets, Docker, VMware, or root privileges.

Run syntax checks:

```sh
python3 - <<'PY'
import ast
from pathlib import Path

for path in sorted(Path("src").rglob("*.py")) + sorted(Path("scripts").glob("*.py")):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
print("Python syntax checks passed")
PY

bash -n scripts/install.sh
```

## 6. Run from the extracted directory

No installation is required for offline review:

```sh
scripts/h1-ro --help
scripts/files-preflight --help
scripts/files-request-broker --help
scripts/files-broker-client --help
```

The wrapper scripts load Python modules from the checkout's `src/` directory.

## 7. Optional system-wide installation

Review the installer first:

```sh
sed -n '1,220p' scripts/install.sh
```

Then install:

```sh
sudo scripts/install.sh
```

Default locations:

| Purpose | Path |
| --- | --- |
| Application source and disabled examples | `/opt/codex-hackerone-investigator/` |
| Command symlinks | `/usr/local/bin/` |
| Emergency STOP | `/var/lib/files-research/runtime/STOP` |

The installer does **not** create `/var/lib/files-research/config/`, copy a live
allowlist, create a service account, install the example systemd unit, or start a
service.

Choose alternate application and command locations when necessary:

```sh
sudo scripts/install.sh \
  --prefix /opt/codex-hackerone-investigator \
  --bin-dir /usr/local/bin
```

Both paths must be absolute. The installer refuses symlink destinations and refuses
to replace an existing regular command file.

## 8. Verify the installed commands

```sh
command -v h1-ro
command -v files-preflight
command -v files-request-broker
command -v files-broker-client

h1-ro --help
files-preflight --help
files-request-broker --help
files-broker-client --help

test -f /var/lib/files-research/runtime/STOP
```

The last command should succeed. Do not remove STOP as an installation test.

## 9. Prepare private configuration safely

Live configuration, credentials, approvals, policy snapshots, broker responses, and
investigation evidence must remain outside the repository.

### Create a dedicated service identity

The installer intentionally does not create accounts. For a reviewed Stage 4 host
deployment, create a non-login identity if one does not already exist:

```sh
getent passwd files-research >/dev/null || \
  sudo useradd --system \
    --home-dir /var/lib/files-research \
    --create-home \
    --shell /usr/sbin/nologin \
    files-research
```

Do not give this account a password, interactive shell, sudo access, or membership in
Docker or virtualization administration groups.

### Create private directories

```sh
sudo install -d -o files-research -g files-research -m 0700 \
  /var/lib/files-research/config \
  /var/lib/files-research/config/secrets \
  /var/lib/files-research/runtime \
  /var/lib/files-research/evidence

sudo install -o files-research -g files-research -m 0600 \
  /dev/null /var/lib/files-research/runtime/STOP

sudo install -o files-research -g files-research -m 0600 \
  config/allowlist.template.json \
  /var/lib/files-research/config/allowlist.json
```

The copied allowlist remains disabled and target-free. Keep it that way until all
private review steps are complete.

### Configuration review checklist

Before any activation decision:

1. Save and hash the current program policy privately.
2. Confirm explicit authorization for the exact researcher-owned host.
3. Record fresh, timezone-aware verification and approval timestamps.
4. Add only exact reviewed URLs with query strings.
5. Approve only required methods and hypothesis identifiers.
6. Resolve and independently verify current public IP addresses.
7. Store the API key in a separate mode-`0600` file owned by `files-research`.
8. Keep top-level `enabled` and `broker.execution_enabled` false during review.
9. Keep STOP present.
10. Run the complete offline test suite again.

The public project intentionally does not provide a one-command activation procedure.

## 10. Read-only HackerOne credentials

The `h1-ro` workflow uses the interactive researcher's identity, not the broker
service account:

```sh
install -d -m 0700 "$HOME/.config/hackerone"
install -m 0600 /dev/null "$HOME/.config/hackerone/username"
install -m 0600 /dev/null "$HOME/.config/hackerone/token"
```

Populate those files from a trusted terminal. Never store them under the repository,
pass them as command-line arguments, or commit them.

## 11. Updating

For a Git checkout:

```sh
git status --short
git pull --ff-only
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
sha256sum -c RELEASE-MANIFEST.sha256
sudo scripts/install.sh
```

For a ZIP installation:

1. Download the new archive into a new directory.
2. Verify its manifest and run its offline tests.
3. Review release notes and configuration changes.
4. Run the new installer.
5. Confirm STOP is still present.

The installer refreshes application files but does not migrate or activate private
configuration. Back up private configuration and evidence according to your engagement
requirements; never copy them into the public checkout.

## 12. Troubleshooting

### `permission denied` while reading configuration

The invoking identity must own the configuration directory and file. Directories must
be mode `0700`; configuration and credential files must be `0600` or stricter. Symlinks
are refused.

### `scope guard is disabled pending manual approval`

This is expected for an unchanged public template. Do not bypass it. Complete a private
review and use a short-lived approval window.

### `no exact researcher-owned targets are approved`

The target list is empty or entries remain unapproved. Confirm ownership and current
program scope before editing a private copy.

### `active broker targets require at least one exact approved URL`

Stage 4 will not accept a prefix-only active target. Add only the exact reviewed URLs
required by the approved hypothesis.

### `emergency stop is active`

STOP exists. This is fail-closed behavior. Review the engagement state and planned
request rather than deleting STOP to silence the error.

### Installed command not found

Confirm the selected `--bin-dir` is on `PATH` and inspect the symlink:

```sh
ls -l /usr/local/bin/h1-ro
```

### No service is installed

This is intentional. `systemd/files-broker.service.example` is reference material and
requires local security review. The installer never copies or enables it.

### Tests create `__pycache__`

Use `PYTHONDONTWRITEBYTECODE=1` as shown above. Generated caches are ignored by Git and
must not be included in a release archive.

## 13. Removal

There is no automated uninstall command because deployments may contain private
evidence or configuration that must be preserved. Review exact paths before removal:

- command symlinks in the selected `--bin-dir`;
- the selected application prefix;
- `/var/lib/files-research/`, subject to evidence-retention requirements.

Do not delete private investigation material without the engagement owner's approval.
