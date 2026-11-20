# Delivery stages

## Stage 1 — read-only acquisition

Completed. The HackerOne client exposes only documented read endpoints, validates
paths and query parameters, applies conservative rate controls, and rejects malformed
pagination. Credentials must come from private files with strict ownership and modes.

## Stage 2 — normalization and review

Completed. Program data is normalized and ranked for human review. Raw responses,
derived JSON, reports, and SHA-256 manifests remain inside the private case root.
Ranking is triage assistance, never authorization to test.

## Stage 3 — offline scope preparation

Completed. The scope guard validates fresh policy metadata, explicit researcher
approval, exact owned hosts, exact URLs, approved DNS results, methods, request sizes,
and a shared rate limit. The public templates are disabled and empty.

## Stage 4 — host request broker

Completed. A local Unix-socket broker requires exact approved URLs and injects a
host-held Files.com credential only after validation, connects directly to an approved IP with TLS hostname verification,
never follows redirects, and writes redacted metadata. An emergency STOP blocks
execution. The sample unit is disabled by construction and is not installed automatically.

## Stage 5 — VMware integration

Unfinished. Guest-to-host transport, mutual TLS provisioning, VM firewall deployment,
host vmnet policy, lifecycle automation, and end-to-end installation have not reached
the support threshold for public release. Stage 5 implementation files are excluded.
