# Internal Architecture

The backend follows one dependency direction:

```text
HTTP API -> CCSDS frame service -> raw protection core -> key resolver -> TPM
                         |                              |
                         +------ SecurityState --------+
```

`securitystate` is the only persistence module. It owns the SQLite schema and
atomic operations for TC counters, SA transitions, AOS replay acceptance,
wrapped roots, and audit chains. Callers depend on narrow interfaces owned by
the CCSDS, protection, resolver, audit, or ops package; they do not issue SQL.

The supported API packages are:

- `api/ccsds`: TC protect, AOS unprotect, and read-only runtime status.
- `api/auditapi`: read-only audit events and chain verification.
- `api/ops`: read-only service and SQLite diagnostics.
- `api/middleware`: authentication, strict plane/scope matrix, body limits, and admission control.

The protocol seam is `protocol/ccsds`. A future mission protocol may build a
new frame module over `application/protection`, but no generic public crypto
API or generic persistence model is retained for that possibility.

Rules:

- Runtime modules never return plaintext CRK, protocol root, or derived working
  keys. The offline provisioner is the sole explicit seam allowed to create a
  mode-0600 flight NVM artifact containing flight roots.
- Allocate counters and commit replay acceptance transactionally before success.
- Treat unknown suites, states, fields, routes, and configuration keys as errors.
- Provision or mutate SAs only with the offline `cmd/ccsds-provision` tool.
- Keep all runtime operations endpoints read-only.
