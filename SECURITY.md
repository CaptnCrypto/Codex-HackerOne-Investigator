# Security Policy

## Supported scope

Stages 1–4 are the supported public components. Stage 5 VMware integration is
unfinished and receives no security-support claim.

## Reporting a vulnerability

Do not include secrets, live targets, private HackerOne program material, customer
data, or exploit evidence in a public issue. Contact the repository owner through a
private channel listed on the eventual GitHub repository profile. If no private
channel is published, open a minimal issue asking for one without disclosing details.

Include:

- affected component and version or commit;
- a safe, offline reproduction using synthetic data;
- security impact and assumptions;
- suggested remediation, if known.

## Operational security

- Never store API keys, cookies, tokens, passwords, or signed URLs in this repository.
- Never replace the empty public allowlist with a live target configuration.
- Keep evidence and program snapshots in a private case directory.
- Treat the emergency STOP file as a required control, not a convenience flag.
- Do not expose the broker Unix socket to untrusted users.
- Re-verify program policy, scope, exact targets, DNS, rate limits, and approval before each live window.
- Do not enable the example systemd service without a local security review.

## Security limitations

This project cannot establish authorization, prevent a privileged local user from
bypassing it, or make an unsafe host trustworthy. The broker is a narrow application
control, not a complete network sandbox or substitute for an egress firewall.
