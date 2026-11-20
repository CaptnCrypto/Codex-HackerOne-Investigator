# Architecture

```text
HackerOne read API -> h1-ro -> private raw snapshots -> normalize/rank -> private reports

reviewed envelope -> Unix socket -> request broker -> scope guard -> shared limiter
                                         |                |
                                         |                +-> exact host/URL/method/DNS
                                         +-> host-held secret + direct TLS + redacted audit
```

The read-only workflow and request broker are separate trust domains. `h1-ro` assists
program discovery and preserves private snapshots. The broker handles only envelopes
already reviewed against a private allowlist.

The public repository contains code and disabled templates. Live configuration,
credentials, authorization records, policy snapshots, and evidence belong outside it.

The broker does not accept arbitrary URLs or credential headers from a client. It
revalidates scope, approval, target ownership metadata, DNS results, request method,
body limits, STOP state, and the global rate slot before transport.
