# Project roadmap

This roadmap describes the public project's implementation status and proposed work.
It is not a promise of delivery dates. Security controls take priority over feature
speed.

## Delivered in v0.1.0

### Stage 1: read-only program discovery

- Read-only HackerOne API helper.
- Local credential loading outside the repository.
- Program and structured-scope retrieval.
- Normalization, filtering, ranking, and investigator-facing summaries.
- Offline tests with synthetic fixtures.

### Stage 2: preparation and policy checks

- Target and policy preparation models.
- Default-deny configuration validation.
- Scheme, host, port, path, method, approval, and rate-policy checks.
- Emergency STOP enforcement and negative tests.
- No direct live execution from the preparation tooling.

### Stage 3: controlled preflight

- Approved-target and optional exact-URL validation.
- Public-IP pinning and TLS-related policy checks.
- Shared rate-limiter state and approval metadata.
- CLI commands for configuration validation, URL checks, and rate-slot acquisition.

### Stage 4: controlled HTTPS request broker

- Unix-domain socket client and broker architecture.
- Mandatory exact-URL, exact-host, method, hypothesis, and approval constraints.
- DNS pinning, TLS validation, no redirects, bounded requests, and metadata-focused
  logs.
- STOP checks around preparation, rate limiting, transport, and response handling.
- Disabled-by-default configuration and service examples.

Stages 1–4 are reusable and offline-tested. Their presence does not mean live target
testing is enabled or approved.

## Stage 5: VMware worker integration — unfinished

Stage 5 remains planning documentation only. The repository does not include a
production VMware worker, VM lifecycle controller, isolated network policy, guest
image, certificate enrollment system, or deployment automation.

Completion would require, at minimum:

- a disposable and reproducible worker image;
- enforced egress isolation independent of application policy;
- authenticated broker-to-worker communication and certificate rotation;
- immutable task envelopes with narrowly scoped authorization;
- safe snapshot, reset, and evidence-export procedures;
- secret injection that leaves no credentials in images or logs;
- resource limits, health checks, timeouts, and fail-closed teardown;
- auditable operator approval and emergency-stop propagation; and
- threat-model review plus adversarial offline/integration tests.

Stage 5 must not be represented as complete until those controls are implemented and
independently reviewed.

## Proposed future improvements

### Security assurance

- Property-based tests for URL canonicalization and scope boundaries.
- Fuzzing of broker envelopes and parser failure paths.
- Reproducible builds and signed release artifacts.
- Software bill of materials and automated dependency/license review if dependencies
  are introduced.
- Additional independent secret-scanning guidance for release maintainers.

### Developer experience

- Stable machine-readable CLI output schemas.
- More synthetic example configurations and troubleshooting diagnostics.
- Better type coverage and structured error codes.
- Packaging validation across supported Debian and Ubuntu versions.
- Documentation link and Markdown linting in CI without enabling network activity.

### Investigator workflow

- Stronger local evidence-integrity helpers.
- Redaction-aware metadata export and report templates.
- Explicit approval-expiry and revocation workflows.
- Human-review checkpoints for every transition from preparation to execution.

## Non-goals

- Autonomous exploitation or report submission.
- Broad or indiscriminate scanning.
- Bypassing program rules, authorization, scope, or rate limits.
- Treating application checks as a substitute for network isolation.
- Shipping credentials, target data, or private investigation evidence.

See [Stages](STAGES.md), [Architecture](ARCHITECTURE.md),
[Safety model](SAFETY_MODEL.md), and [VMware Stage 5](VMWARE_STAGE5.md) for details.
