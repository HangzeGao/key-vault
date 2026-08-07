# Production Security Gate

This file is a release gate, not a claim that the current repository is ready
for production. A production process fails closed unless configuration declares
and provides the following controls:

- PostgreSQL with a non-empty DSN and externally managed PITR.
- Native TSS/ESAPI TPM access with an explicit TCTI.
- One active public plane per process: `management`, `data`, or `ops`.
- TLS 1.3 server identity and a client CA for mandatory mTLS.
- JWT/OIDC issuer, audience, HTTPS JWKS endpoint, asymmetric algorithms
  (`RS256`/`ES256`), and a maximum token lifetime of 15 minutes.
- HMAC and static-token authentication disabled.
- Exact HTTPS CORS origins; an empty list means same-origin only.
- Persistent Ed25519 policy trust bundle and signed policy package.
- A deployment-specific audit-redaction pepper.
- Audit WAL, PITR declaration, and a readable restore-drill evidence file.

See `config.production.example.yaml` for the complete configuration shape.

## Implemented fail-closed checks

- Production refuses memory storage, software/shell TPM providers, logical or
  all-plane listeners, plain HTTP, missing mTLS material, ephemeral policy
  trust, symmetric JWT algorithms, static tokens, HMAC, wildcard CORS, and
  missing recovery evidence.
- JWKS is fetched over a pinned HTTPS origin, cached atomically, bounded to
  1 MiB, and unknown-key refresh is throttled.
- JWT verification requires `typ=JWT`, `kid`, `iss`, `aud`, `sub`, `iat`,
  `exp`, an allowed asymmetric algorithm, and a bounded lifetime.
- Browser bearer credentials are held in memory and are not written to
  `localStorage`.
- Every operation requires an explicit `key_id`. The suite catalog and signed
  policy enforce `AUTH_ONLY` → CMAC, `ENCRYPT_ONLY` → CTR, and
  `AUTH_ENCRYPT` → GCM. A service type cannot be configured independently from
  its suite, and ECB cannot be enabled by a signed policy.
- GCM and CTR consume durable, never-recycled uniqueness leases. CTR expands
  each leased 96-bit prefix into a 128-bit initial counter. CMAC verification
  uses a full-length tag, constant-time comparison, and binds suite, key ID,
  key version, policy version, and message length.
- Management, data, and ops HTTP routes are registered only in their selected
  process. The lifecycle scheduler runs only on the management plane.

## Blocking before a real release

The following require operational or architectural work and cannot be satisfied
by a boolean configuration value:

1. Implement a separately deployed Key Plane RPC boundary. The current
   `keyresolver` is a deep internal module but is still in-process with each
   public plane.
2. Implement transactional CRK rotation that rewraps every live KeyVersion,
   atomically activates the new CRK, invalidates leases, and survives rollback.
3. Implement node enrollment and CRK-envelope distribution for every
   `(node, plane)` TPM identity. The current bootstrap only creates or loads the
   configured node's envelope.
4. Run PostgreSQL failover/PITR restore drills, native TPM restart/PCR-change
   drills, JWKS rotation drills, and multi-process plane deployment tests in CI.
5. Build and test the frontend from `package-lock.json` in a clean, networked
   CI runner.

Do not approve a production release while any item above is open.

## Release verification

Scan logs, structured errors, audit metadata, UI snapshots, database dumps, and
temporary directories for tokens, plaintext, DEK/CRK, full envelopes, wrapped
material, and authorization headers. Exercise failed database connections,
migrations, concurrent updates, transaction rollback, corrupted policy/JWKS
documents, invalid TCTI/PCR policy, TPM restart, and corrupted CRK envelopes.
Ops mutations must demonstrate requested/final audit pairs and fail closed when
either audit write is unavailable.
