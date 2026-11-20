# Stage 5 VMware integration — unfinished

VMware integration is not part of this release. The prepared case contained exploratory
guest/client, bridge, firewall, certificate-provisioning, and deployment material, but
the complete integration and operational review are unfinished.

The public package therefore does **not** install or support:

- a VMware guest client;
- a vmnet listener or host bridge;
- guest or host firewall automation;
- mutual-TLS certificate provisioning;
- USB transfer workflows;
- a VMware systemd service.

Completion requires a documented network model, reproducible installation on supported
VMware versions, certificate lifecycle and revocation procedures, default-deny firewall
validation, end-to-end negative tests, upgrade/uninstall behavior, and an independent
security review. Until then, do not expose the Stage 4 broker beyond its local Unix socket.
