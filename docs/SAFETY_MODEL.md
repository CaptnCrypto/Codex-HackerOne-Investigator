# Safety model

## Goals

- fail closed when scope, approval, freshness, DNS, permissions, or configuration is ambiguous;
- keep credentials out of process arguments, public configuration, logs, and client envelopes;
- constrain requests to exact reviewed URLs and methods;
- provide a manual emergency STOP and conservative cross-process rate limit;
- preserve only redacted operational metadata in broker evidence.

## Non-goals

- proving that the operator has legal authorization;
- containing a malicious root user or another process with equivalent privileges;
- replacing an egress firewall, disposable lab, or host hardening;
- automatically discovering or exploiting vulnerabilities;
- supporting arbitrary vendors or customer targets without code and policy review.

## Trust boundaries

The operator prepares policy and approval metadata. A dedicated service identity owns
private credential and runtime files. Clients may submit non-secret envelopes through
a private Unix socket but cannot choose credentials or bypass the exact request list.

If unexpected customer data, credentials, code execution, service instability, policy
ambiguity, or target ownership ambiguity appears, stop immediately and preserve only
the minimum redacted evidence required by the authorized engagement.
