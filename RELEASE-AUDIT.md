# Release audit

Documentation-finalization review: `2026-11-20T02:15:56-05:00`

This distribution was prepared from a private investigation case by an explicit
allowlist, not by copying the case tree wholesale. This review covers the prospective
public repository contents on branch `docs/public-project-finalization`.

## Included

- reusable Python source for Stages 1–4;
- offline unit and negative tests using synthetic fixtures;
- disabled, target-free public configuration templates;
- beginner-facing documentation, contribution guidance, and the project roadmap;
- a non-activating installer and disabled service example; and
- a least-privilege GitHub Actions workflow that runs only offline checks.

## Excluded

- private API snapshots and program-policy captures;
- case evidence, reports, screenshots, logs, timelines, and exports;
- credentials, tokens, cookies, private keys, and live secret-file contents;
- live allowlists, target IPs, approval records, and researcher identifiers;
- case-specific hypothesis preparation and execution scripts;
- Stage 5 VMware runtime, certificate, firewall, and deployment components;
- Python bytecode, caches, Git metadata, and build output.

## Verification performed

- every regular distribution file enumerated and reviewed by path and type;
- all 65 source tests and public-release assertions run offline;
- Python AST parsing and Bash syntax validation;
- Markdown local-link and repository-path checks;
- workflow review for read-only token permissions, no secrets, no privileged
  containers, no deployment, and no live target execution;
- exact searches for private case paths, researcher identifiers, live target labels,
  case-specific hypothesis names, and policy-snapshot identifiers;
- pattern scans for common cloud, GitHub, Slack, JWT, bearer/basic-auth, and PEM
  secrets;
- URL, email-like string, absolute-path, and IPv4 review;
- configuration assertions that both public templates are disabled, execution is
  disabled, source snapshots are unset, and target arrays are empty;
- Stage 5 runtime-name exclusion assertions;
- independent local pattern and entropy-oriented scan over the prospective Git file
  set; and
- SHA-256 release-manifest regeneration and verification after documentation changes.

The synthetic strings in tests are deliberately labeled and do not authenticate to
any service. Automated secret scanners are useful additional defense but cannot prove
the absence of all secrets; human review remains required before publication.

## Final findings

- All 65 offline tests pass.
- Apache-2.0 is included as the standard `LICENSE` and referenced by package metadata.
- The broker requires a non-empty exact-URL allowlist in addition to method,
  hypothesis, approval, DNS-pin, credential, rate, and STOP checks.
- The installer creates STOP and does not install, enable, or start systemd services;
  it contains no firewall or scanning commands.
- Public configurations remain disabled, broker execution remains disabled, and
  target lists remain empty.
- The GitHub Actions workflow uses only `actions/checkout@v4`, disables persisted
  credentials, grants `contents: read`, and runs offline validation commands.
- No matched credential, private case marker, personal identifier, live target, or
  private program snapshot was found.
- Gitleaks, TruffleHog, detect-secrets, git-secrets, ggshield, Trivy, and Semgrep were
  not installed, and no package or external scanning service was used. An independent
  local scanner was used as the available equivalent.

## Remaining publication gates

- repository owner attestation that every contribution is original, owned by the
  publisher, or otherwise redistributable under Apache-2.0;
- repository owner confirmation that GitHub Actions is enabled and permits the
  GitHub-owned `actions/checkout` action under the repository's current policy;
- human review of the final Git status and diff before any commit; and
- explicit owner approval before commit, push, release, or publication.
