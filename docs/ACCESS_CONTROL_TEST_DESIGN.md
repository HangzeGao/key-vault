# Access control test design

This contract is mandatory for changes to Data/Ops authentication, source-IP
admission, TLS clients, plane routing, token generation, or rejection telemetry.
Such changes are security-critical and require the complete `make release-gate`.

## Fixed security contract

- Exactly one Data identity and one Ops identity exist per deployment.
- Tokens are independent canonical 256-bit unpadded base64url values.
- The service stores only lowercase SHA-256 token verifiers.
- Data is admitted only from one configured unicast `RemoteAddr`; forwarded-IP
  headers never affect the decision.
- Ops clients connect only to loopback, reject redirects, pin the server
  certificate, and negotiate TLS 1.3 or newer in production.
- There is no legacy raw-token document, dynamic scope assignment, CIDR source
  range, dual-token grace window, or mTLS fallback.

## Required automated checks

| Boundary | Required evidence |
| --- | --- |
| Generator | independent tokens; `0600`; exclusive creation; no token in stdout/stderr or verifier document; partial failure cleanup |
| Verifier | exact token format; fixed principals/scopes; constant-time digest comparison; malformed/duplicate/zero verifier rejection; no rotation grace |
| Data admission | source rejection precedes token processing and body read; `X-Forwarded-For` ignored; invalid `RemoteAddr` rejected |
| HTTP auth | missing, malformed, duplicate, wrong-plane and wrong-scope credentials fail closed |
| TLS | TLS 1.2 handshake rejected; TLS 1.3 accepted; client requires pinned certificate; redirects rejected |
| Ops | only loopback origins; token/CA symlinks rejected; bounded non-secret rejection counters visible |
| TC retransmission | repeated protection of the same plaintext frame preserves its frame sequence number but allocates a fresh IV and ciphertext |

`internal/auth/access` must maintain at least 95% statement coverage. The
coverage is measured independently in `scripts/coverage_gate.sh` so unrelated
cryptographic packages cannot mask a regression. The complete release gate also
runs Go race tests, vulnerability scanning, TC ground-to-flight vectors,
external SM4 vectors, C hardening, C/Go coverage, and ARMv7/QEMU differential
tests.

## Manual deployment evidence

Before production acceptance, record the exact Data interface/source address,
host-firewall rule, TLS certificate fingerprint and expiry, token installation
owners/modes, and successful calls from the allowed host. Also record that a
request from another host is rejected before application authentication. Never
include token values in the evidence.
