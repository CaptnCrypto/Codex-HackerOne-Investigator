# Release audit

Final pre-publication review: `2026-11-20T01:12:03-05:00`

This distribution was prepared from a private investigation case by an explicit
allowlist, not by copying the case tree wholesale.

## Included

- reusable Python source for Stages 1–4;
- offline unit and negative tests using synthetic fixtures;
- disabled, target-free public configuration templates;
- documentation, a non-activating installer, and a disabled service example.

## Excluded

- private API snapshots and program-policy captures;
- case evidence, reports, screenshots, logs, timelines, and exports;
- credentials, tokens, cookies, private keys, and live secret-file contents;
- live allowlists, target IPs, approval records, and researcher identifiers;
- case-specific hypothesis preparation and execution scripts;
- Stage 5 VMware runtime, certificate, firewall, and deployment components;
- Python bytecode, caches, Git metadata, and build output.

## Verification performed

- every regular file enumerated and reviewed by type and path;
- source tests and public-release assertions run offline;
- Python compilation and shell syntax checks;
- exact searches for private case paths, researcher identifiers, live target labels,
  case-specific hypothesis names, and policy-snapshot identifiers;
- pattern scans for common cloud, GitHub, Slack, JWT, bearer/basic-auth, and PEM secrets;
- URL, email-like string, absolute-path, and IPv4 review;
- configuration assertions that both public templates are disabled, execution is
  disabled, source snapshots are unset, and target arrays are empty;
- Stage 5 runtime-name exclusion assertions.
- independent local pattern and entropy scan over the prospective Git file set;
- Git prospective-file review from the existing unborn repository;
- Apache-2.0 text sourced from the operating system's `base-files` package.

The synthetic strings in tests are deliberately labeled and do not authenticate to
any service. Automated secret scanners are useful additional defense but cannot prove
the absence of all secrets; human review remains required before publication.

## Final findings

- All 65 offline tests pass and the Python wheel builds successfully.
- Apache-2.0 is included and referenced by package metadata.
- The active broker now requires a non-empty exact-URL allowlist in addition to the
  existing method, hypothesis, approval, DNS-pin, credential, rate, and STOP checks.
- The installer creates STOP and does not install, enable, or start systemd services;
  it contains no firewall or scanning commands.
- No matching secret, private case marker, personal identifier, live target, or private
  program snapshot was found.
- Gitleaks, TruffleHog, detect-secrets, git-secrets, ggshield, Trivy, and Semgrep were
  not installed, and no package or external service was used. A separate local scanner
  reported one candidate: the explicitly synthetic `FAKE_TOKEN` regression-test value
  `fake-token-value-never-send`; manual review confirmed it is not a credential.

## Remaining publication gates

- repository owner attestation that all contributions may be redistributed under Apache-2.0;
- repository owner review of the private security-report contact method;
- human review of the final prospective Git file list before the first commit;
- repeat `scripts/audit-release.py`, the offline test suite, and manifest verification
  immediately before publication.
