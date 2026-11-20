# Installation

## Supported baseline

- Linux with Python 3.11 or newer
- A dedicated non-login service identity for broker deployments
- A private case directory for all API snapshots and evidence
- Explicit authorization for any active testing

The core runtime uses only the Python standard library. VMware integration is not
part of the supported installation.

## Review and test first

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q src scripts
```

All tests are offline. Do not place credentials in the repository or test fixtures.

## Run from the checkout

The scripts resolve modules from the repository's `src/` directory:

```sh
scripts/h1-ro --help
scripts/files-preflight --help
scripts/files-request-broker --help
scripts/files-broker-client --help
```

`files-request-broker` will not perform an approved request when used with the shipped
configuration because it is disabled, has no targets, and has no credentials.

## System install

Inspect `scripts/install.sh`, then run:

```sh
sudo scripts/install.sh
```

Defaults:

- application: `/opt/codex-hackerone-investigator`
- command links: `/usr/local/bin`
- disabled templates: `/etc/codex-hackerone-investigator`
- runtime STOP: `/var/lib/files-research/runtime/STOP`

Override the application prefix and command directory without editing the script:

```sh
sudo scripts/install.sh \
  --prefix /opt/codex-hackerone-investigator \
  --bin-dir /usr/local/bin
```

The installer refuses symlink destinations, copies no credentials, does not create a
live allowlist, and does not install, enable, or start systemd units. The service file
under `systemd/` is an example requiring local review and a dedicated service account.

## Private configuration checklist

1. Create a dedicated non-login broker account and private state directories.
2. Keep configuration and credential directories mode `0700`; files mode `0600`.
3. Copy `config/allowlist.template.json` to a private location.
4. Replace metadata only after reviewing the current program policy.
5. Add an exact owned host, exact approved IPs, and exact approved request URLs.
6. Keep `enabled` and `broker.execution_enabled` false during review.
7. Validate offline with `files-preflight validate-config` only after intentionally enabling the private copy.
8. Keep `/var/lib/files-research/runtime/STOP` present until the approved execution window.

Never commit the resulting private configuration, secret file, evidence, or response.

## Removal

There is intentionally no automated uninstall script. Review and remove the exact
paths you selected, preserving any private evidence required by your engagement.
