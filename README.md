# Codex HackerOne Investigator

Codex HackerOne Investigator is a defensive research toolkit for organizing
HackerOne program discovery and placing strict controls around reviewed API requests.
It is intended for researchers who want reproducible workflows, private evidence
handling, explicit scope boundaries, and a human approval step before network activity.

This is a public preview. Stages 1–4 are implemented and offline-tested. Stage 5,
which is intended to add an isolated VMware worker, is unfinished and is not included
as a supported runtime component.

> [!WARNING]
> This project does not grant authorization to test any system. Use it only on assets
> you own or are explicitly authorized to test. Re-check the current program policy,
> scope, rate limits, and stop conditions before every research session.

## Why this project exists

Security research often mixes program discovery, target selection, credentials,
requests, and evidence in one loosely controlled environment. This project separates
those concerns:

- `h1-ro` performs a narrowly allowlisted, read-only HackerOne API synchronization.
- The Stage 3 tools validate policy metadata, owned targets, URLs, and rate controls
  without sending HTTP requests.
- The Stage 4 broker accepts reviewed request envelopes over a private Unix socket,
  injects a host-held credential only after validation, and connects directly to an
  approved IP with TLS hostname verification.
- Private API responses, credentials, live allowlists, approvals, and evidence remain
  outside the public repository.

## Features

### Read-only HackerOne synchronization

- Fixed HackerOne API origin and documented read endpoints.
- Strict path and query validation.
- Bounded pagination, response sizes, retries, and timeouts.
- Program and structured-scope normalization.
- Opportunity ranking for investigator review.
- Private raw snapshots, derived artifacts, reports, and SHA-256 manifests.

### Scope and execution controls

- Disabled and target-free public configurations.
- Fresh policy-verification and researcher-approval metadata.
- Exact researcher-owned host validation.
- Exact approved URL requirement for active broker targets.
- Explicit HTTP methods, hypotheses, approval references, and public IP pins.
- Conservative shared rate limiter capped at 1.5 requests per second.
- Request and response size limits.
- Emergency `STOP` checks throughout request execution.

### Request broker protections

- Private Unix-domain socket interface.
- Host-side credential loading from strict mode-`0600` files.
- Rejection of client-supplied authentication and routing headers.
- Direct TLS transport that ignores proxy environment variables.
- No automatic redirect following.
- Fail-closed behavior for DNS changes, transport errors, throttling, and server errors.
- Metadata-focused audit records that omit URLs, queries, bodies, and credentials.

## Architecture

```text
                         STAGES 1–2

  HackerOne read API ──> h1-ro ──> private case directory
                                   ├── raw snapshots
                                   ├── normalized artifacts
                                   ├── opportunity report
                                   └── SHA-256 manifest

                         STAGES 3–4

  reviewed JSON envelope
           │
           ▼
  private Unix socket ──> request broker ──> direct TLS request
                              │                    │
                              ├── emergency STOP  └── approved pinned IP
                              ├── exact host/URL/method
                              ├── current approval metadata
                              ├── DNS and rate controls
                              └── host-held credential
```

The read-only synchronization and request broker are separate workflows. Running
`h1-ro` does not start the broker, and installing the project does not activate either
workflow. See [Architecture](docs/ARCHITECTURE.md) and the
[Safety model](docs/SAFETY_MODEL.md) for the trust boundaries.

## Project status

| Stage | Status | Scope |
| --- | --- | --- |
| 1 | Complete | Read-only HackerOne transport and credential-file validation |
| 2 | Complete | Normalization, ranking, private output, and integrity manifests |
| 3 | Complete | Offline scope guard, approval validation, and shared rate limiting |
| 4 | Complete | Local request broker, direct TLS, audit metadata, and STOP controls |
| 5 | Unfinished | VMware worker isolation, mTLS bridge, and firewall integration |

The public preview is suitable for code review, offline testing, and controlled lab
preparation. It is not an autonomous penetration-testing platform. Read the
[Roadmap](docs/ROADMAP.md) and [Stage descriptions](docs/STAGES.md) for details.

## Requirements

- Debian, Ubuntu, or another Linux distribution.
- Python 3.11 or newer.
- Bash and standard Unix utilities.
- Root access only for the optional system-wide installation.
- A private directory outside the repository for credentials, configuration, and
  investigation output.

The Python runtime uses only the standard library.

## Quick start from a checkout

```sh
git clone https://github.com/CaptnCrypto/Codex-HackerOne-Investigator.git
cd Codex-HackerOne-Investigator

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v

python3 scripts/audit-release.py .
scripts/h1-ro --help
scripts/files-preflight --help
```

For ZIP installation, system-wide installation, updating, and troubleshooting, see
[INSTALL.md](INSTALL.md).

## Supported commands

| Command | Purpose | Network behavior |
| --- | --- | --- |
| `scripts/h1-ro sync` | Synchronize allowed HackerOne program data into a private case | Read-only HTTPS after explicit invocation |
| `scripts/files-preflight validate-config` | Validate a completed private configuration | Offline |
| `scripts/files-preflight check-url` | Check one stdin URL against the private scope guard | Offline |
| `scripts/files-preflight acquire-rate-slot` | Exercise the shared limiter without sending a request | Offline |
| `scripts/files-request-broker` | Start the local Unix-socket broker with explicit paths | Network-capable only with an enabled private configuration and no STOP file |
| `scripts/files-broker-client` | Submit one JSON envelope to a local broker socket and save the response privately | Local Unix socket only |
| `scripts/audit-release.py` | Check the public tree for unsafe files, markers, and enabled configurations | Offline |

### Read-only synchronization example

Create credential files outside the repository:

```sh
install -d -m 0700 "$HOME/.config/hackerone"
install -m 0600 /dev/null "$HOME/.config/hackerone/username"
install -m 0600 /dev/null "$HOME/.config/hackerone/token"
```

Populate them from a trusted terminal. Create a private case directory containing a
single non-empty `CASE_ID=` line in `CASE-INFO.txt`, then run:

```sh
scripts/h1-ro sync \
  --case-root /absolute/path/to/private/case \
  --credentials-dir "$HOME/.config/hackerone"
```

The command writes private data beneath the case's `reports/` and `artifacts/`
directories. Never use real credentials in CI, shell history, command arguments, or
the public repository.

### Offline preflight examples

The shipped templates are intentionally public, mode `0644`, disabled, and empty.
Create a private copy before validation:

```sh
install -d -m 0700 "$HOME/.config/codex-h1-investigator"
install -m 0600 config/allowlist.template.json \
  "$HOME/.config/codex-h1-investigator/allowlist.json"

scripts/files-preflight validate-config \
  "$HOME/.config/codex-h1-investigator/allowlist.json"
```

An unchanged template must fail closed because it is disabled and has no targets.
Do not enable a private configuration until its policy, ownership, approval, exact
URLs, methods, hypotheses, IP pins, and credential path have been reviewed.

Check a single URL through standard input so it does not appear in process arguments:

```sh
printf '%s\n' 'https://owned-lab.example.invalid/api?example=1' | \
  scripts/files-preflight check-url \
  "$HOME/.config/codex-h1-investigator/allowlist.json"
```

The placeholder URL above is expected to be denied unless the private configuration
contains that exact reviewed value.

## Safety controls

- Active broker execution requires both top-level `enabled: true` and
  `broker.execution_enabled: true` in a private configuration.
- Public templates contain no targets or approval metadata.
- The installer creates `/var/lib/files-research/runtime/STOP` and does not install,
  enable, or start a systemd service.
- The example service has a `ConditionPathExists` guard that prevents startup while
  STOP exists.
- The broker checks STOP before preparation, after rate limiting, before transport,
  and after transport.
- Unexpected DNS results and availability signals engage STOP.
- Stage 5 VM networking and firewall automation are not distributed.

These are defense-in-depth controls, not a substitute for authorization, egress
filtering, disposable lab infrastructure, host hardening, or investigator judgment.

## Repository layout

```text
config/        Disabled configuration templates and stop conditions
docs/          Architecture, safety model, stages, roadmap, and VMware status
scripts/       User-facing commands, installer, and release audit
src/h1ro/      HackerOne read-only synchronization and ranking
src/filesprep/ Scope guard, rate limiter, broker, and local service
systemd/       Disabled example service definition
templates/     Generic private-engagement checklists and metadata templates
tests/         Offline unit, negative, and distribution tests
```

## Troubleshooting

### `ModuleNotFoundError: h1ro` or `filesprep`

Run commands from the repository root through the scripts under `scripts/`, or set
`PYTHONPATH=src` when invoking tests directly.

### Configuration permission errors

Private configuration and secret directories must be owned by the invoking service
identity and have mode `0700`. Files must be regular, non-symlink files with mode
`0600` or stricter.

### `scope guard is disabled pending manual approval`

That is the expected result for the public template. Complete and review a private
copy; never modify the public template into a live allowlist.

### Broker reports `emergency stop is active`

STOP is working as designed. Do not remove it merely to make a command succeed.
Confirm authorization, policy freshness, configuration, service identity, and the
exact planned request before changing runtime state.

### The installer refuses an existing command path

The installer will not replace a regular file in the selected binary directory.
Review the existing command and select a different `--bin-dir` if appropriate.

### No systemd service appears after installation

This is intentional. The repository provides only a reviewed example. Installation
does not copy it into systemd or enable a service.

## Limitations

- Stage 5 VMware worker isolation is unfinished and unsupported.
- The broker is Files.com-specific and is not a general-purpose HTTP proxy.
- The scope guard cannot prove legal authorization or asset ownership.
- A privileged local user can bypass application-level controls.
- The project does not enforce a host firewall or complete network sandbox.
- Public CI runs only offline tests and does not validate live target behavior.
- The public preview has not received an independent professional security audit.

## Documentation

- [Installation guide](INSTALL.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Safety model](docs/SAFETY_MODEL.md)
- [Delivery stages](docs/STAGES.md)
- [Roadmap](docs/ROADMAP.md)
- [Stage 5 VMware status](docs/VMWARE_STAGE5.md)
- [Release audit](RELEASE-AUDIT.md)
- [Apache-2.0 license](LICENSE)

## Contributing and security reports

Development contributions are welcome when they preserve fail-closed behavior and
contain only synthetic fixtures. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a pull request.

Do not disclose vulnerabilities, credentials, private program material, or customer
data in a public issue. Use
[GitHub Private Vulnerability Reporting](https://github.com/CaptnCrypto/Codex-HackerOne-Investigator/security/advisories/new)
as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The license decision and
provenance responsibility are recorded in [LICENSE-PROPOSAL.md](LICENSE-PROPOSAL.md).

---

## Beginner's guide: understanding the workflow

This section complements the technical documentation above. It explains the moving parts without weakening the project's approval and safety requirements.

### What happens in each stage?

1. **Stage 1 — Read-only program discovery:** The `h1-ro` command retrieves permitted HackerOne API information after the operator supplies private credentials and explicitly starts a sync. It does not automatically test targets.
2. **Stage 2 — Normalize and prioritize:** Retrieved program and scope data is transformed into structured artifacts and an opportunity ranking for human review. A high ranking is not authorization.
3. **Stage 3 — Offline preflight:** The operator prepares a **private** configuration and checks that the planned host, URL, method, approvals, policy metadata, and rate limits satisfy the guard. These checks do not send requests to the target.
4. **Stage 4 — Controlled request broker:** An explicitly started local service accepts a reviewed request envelope through a Unix socket. The broker applies scope and transport restrictions before any network request.
5. **Stage 5 — Planned isolation:** The VMware worker and its network isolation controls remain unfinished. Do not treat the design documentation as a functioning sandbox.

### A practical, safe first session

From a fresh checkout, start with the **offline-only** checks:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/audit-release.py .
scripts/h1-ro --help
scripts/files-preflight --help
```

These commands help confirm the environment and show available options. The help commands do not synchronize HackerOne data or authorize live testing. Consult [INSTALL.md](INSTALL.md) before installing globally or configuring a private case.

### Common terms

| Term | Meaning in this project |
| --- | --- |
| **Scope** | The exact systems, hosts, paths, and methods permitted for a particular engagement |
| **Allowlist** | A privately maintained list of explicitly approved targets and constraints |
| **Preflight** | Offline validation performed before considering a live request |
| **Request envelope** | Structured JSON describing a proposed request and its approval context |
| **Broker** | A local gatekeeper that validates and performs tightly controlled network requests |
| **Unix socket** | Local inter-process communication channel between client and broker |
| **TLS** | Encrypted network transport with certificate and hostname verification |
| **IP pinning** | Constraining a request to an approved resolved network address |
| **DNS rebinding** | A risk in which a hostname resolves to a different, potentially disallowed address |
| **Rate limiter** | A mechanism to constrain request frequency |
| **STOP file** | An emergency safety control that prevents or interrupts broker activity |
| **SHA-256 manifest** | A record of file hashes used to detect later changes to artifacts |
| **Fail closed** | Rejecting activity when an approval, safety check, or dependency is uncertain |

### Where does information belong?

| Information | Appropriate location |
| --- | --- |
| Public source code and synthetic tests | This repository |
| Generic templates and design documentation | This repository |
| Real HackerOne credentials | Private, permission-restricted files **outside** the repository |
| Live allowlists, approval records, and engagement policy | Private case/configuration directory |
| API responses, investigation notes, and evidence | Private case directory |
| Public bug reports about the tool | GitHub issues, without secrets or sensitive engagement data |
| Security vulnerabilities in the project | Private vulnerability reporting described in [SECURITY.md](SECURITY.md) |

### Troubleshooting checklist

If a command refuses to run, first identify **which control** rejected it. A missing private configuration, stale approval, unexpected DNS answer, permission error, or active STOP condition is not something to work around casually. Review the applicable section of [INSTALL.md](INSTALL.md), [SAFETY_MODEL.md](docs/SAFETY_MODEL.md), and [STAGES.md](docs/STAGES.md), and correct the underlying authorization or configuration issue before proceeding.

For any actual research activity, retain the current program policy, approved scope, test plan, rate limits, and investigator approval in private records. The repository's public templates are intentionally disabled.

### GitHub terminology for new contributors

- **Clone:** Download a working copy of the repository.
- **Branch:** An isolated line of development.
- **Commit:** A saved version-controlled change.
- **Pull request:** A proposed change that can be reviewed before merging.
- **CI / GitHub Actions:** Automated checks that run on commits or pull requests; this project's public CI is offline-only.
- **Release tag:** A named reference to a particular version of the code.
- **README:** The project overview; the linked guides contain deeper instructions.

### Before opening a pull request

Run the offline tests and release audit, review your diff for secrets and private artifacts, and read [CONTRIBUTING.md](CONTRIBUTING.md). Do not add live targets or make the public templates executable by default. The project is intended to preserve **explicit human control**, not automate authorization decisions.
