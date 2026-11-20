# Codex HackerOne Investigator

Codex HackerOne Investigator is a defensive, fail-closed toolkit for researchers
working under an explicit vulnerability-disclosure or bug-bounty authorization.
It combines a read-only HackerOne opportunity synchronizer with an exact-target
request broker for carefully reviewed API testing.

The public distribution contains the completed reusable work from Stages 1–4.
Active testing is disabled by default. No live target, credential, customer data,
private program snapshot, case evidence, or researcher-specific approval is included.

> **Authorization required:** This software does not grant permission to test any
> system. Use it only against assets you own or are explicitly authorized to test,
> and follow the current program policy, scope, rate limits, and stop conditions.

## What is included

| Stage | Status | Reusable component |
| --- | --- | --- |
| 1 | Complete | Strict read-only HackerOne API transport and credential-file validation |
| 2 | Complete | Program normalization, opportunity ranking, private raw capture, and SHA-256 manifests |
| 3 | Complete | Offline exact-host/exact-request scope guard, policy freshness checks, and shared rate limiter |
| 4 | Complete | Host-side Unix-socket request broker with secret injection, direct TLS, redacted audit records, emergency STOP, and a disabled service template |
| 5 | **Unfinished** | VMware guest-to-host integration; intentionally not included as an installable or supported component |

See [docs/STAGES.md](docs/STAGES.md) and
[docs/VMWARE_STAGE5.md](docs/VMWARE_STAGE5.md) for the boundaries.

## Safety defaults

- Both shipped broker configurations have `enabled: false`.
- Broker execution is separately set to `execution_enabled: false`.
- Target lists are empty and wildcard hosts are rejected.
- An active Stage 4 broker requires a non-empty list of exact approved URLs.
- The installer creates an emergency `STOP` file and never enables or starts a service.
- Credentials are read from private files; they are not command-line arguments or configuration values.
- Client-supplied authentication headers, redirects, proxy routing, unsafe DNS changes,
  and unapproved methods or URLs are denied.
- Offline tests monkeypatch network entry points and must pass before configuration.

## Quick start

Requirements: Linux, Python 3.11 or newer, and standard library tools. The runtime
has no third-party Python dependency.

```sh
python3 -m unittest discover -s tests -v
scripts/files-preflight --help
```

The public configuration templates are intentionally mode `0644`, disabled, and
target-free. `files-preflight validate-config` accepts only a private mode-`0600`
copy in a mode-`0700` directory after it has been deliberately completed and enabled.

For a system installation:

```sh
sudo scripts/install.sh
```

The installer copies code and disabled templates only. Read [INSTALL.md](INSTALL.md)
before creating any private configuration or systemd override.

## Read-only HackerOne synchronization

Create a private credential directory outside the repository:

```sh
install -d -m 0700 "$HOME/.config/hackerone"
install -m 0600 /dev/null "$HOME/.config/hackerone/username"
install -m 0600 /dev/null "$HOME/.config/hackerone/token"
```

Populate those files from a trusted terminal, then run:

```sh
scripts/h1-ro sync \
  --case-root /absolute/path/to/private/case \
  --credentials-dir "$HOME/.config/hackerone"
```

The case root must contain one non-empty `CASE_ID=` entry in `CASE-INFO.txt`.
Outputs are written privately beneath that case's `reports/` and `artifacts/`
directories. Do not run this command in CI with real credentials.

## Broker workflow

The public repository deliberately contains no activation recipe for a live target.
The safe sequence is:

1. Review the current program policy and obtain explicit authorization.
2. Copy a disabled template into a private, mode-`0600` configuration directory.
3. Add only exact researcher-owned targets and exact approved request URLs.
4. Store credentials in separate private files owned by the broker identity.
5. Run the offline test suite and preflight checks.
6. Keep the emergency STOP file present until a human approves one reviewed action.

See [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) for the threat model and limitations.

## Project status

Stages 1–4 are suitable for review and offline use. A real deployment still requires
site-specific security review, private configuration, current policy verification,
and explicit authorization. Stage 5 VMware integration is unfinished and unsupported.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The decision record in
[LICENSE-PROPOSAL.md](LICENSE-PROPOSAL.md) explains the selection and remaining
provenance responsibility.

## Security

Do not open a public issue containing a vulnerability, credential, private program
material, or customer data. Follow [SECURITY.md](SECURITY.md).
