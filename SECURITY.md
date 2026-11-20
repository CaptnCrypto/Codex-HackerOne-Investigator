# Security policy

Codex-HackerOne-Investigator is security-sensitive software. Please report defects
that could weaken scope enforcement, authorization checks, secret handling, transport
validation, rate controls, or the emergency STOP mechanism privately.

## Supported versions

The current public preview is the supported release line:

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier or unreleased private builds | No |

Security fixes may be made only on the default branch and released in a newer version.

## Report a vulnerability privately

GitHub Private Vulnerability Reporting is enabled for this repository. Submit a
private report through the repository's
[security advisory form](https://github.com/CaptnCrypto/Codex-HackerOne-Investigator/security/advisories/new).

Include, when safe:

- the affected version or commit;
- the component and security control involved;
- reproducible steps using synthetic data and offline targets;
- expected and observed behavior;
- potential impact and suggested remediation; and
- whether any credential, private target, or third-party data may have been exposed.

Do not open a public issue for an unpatched vulnerability. Do not include live API
keys, cookies, private HackerOne program data, customer data, or private investigation
evidence in any report. If a safe reproducer requires a secret, describe the required
secret type rather than sending the value.

## Safe research expectations

- Test only systems you own or are explicitly authorized to assess.
- Keep active execution disabled while developing or reproducing an issue.
- Use synthetic fixtures and the offline test suite whenever possible.
- Keep the emergency STOP file present unless a separately authorized, reviewed live
  procedure explicitly requires removal.
- Do not weaken exact-host, exact-URL, DNS-pinning, TLS, method, approval, credential,
  or rate-limit controls to demonstrate a defect.
- Never submit a HackerOne report or contact a target automatically.

## Response process

Maintainers will acknowledge a complete private report when practical, investigate
it, coordinate a fix and disclosure plan, and credit reporters who request attribution.
Response times are not guaranteed for this preview release.

## Scope of this policy

This policy covers the code and documentation in this repository. It does not grant
authorization to test HackerOne, Files.com, GitHub, or any other third-party system.
Authorization must come from the applicable owner or program policy.
