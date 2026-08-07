# Crypto protection modes

The data plane exposes three distinct security service types. The suite catalog
is the single source of truth for the service-to-algorithm mapping; callers
cannot assemble arbitrary mode/MAC combinations.

| Service type | Algorithm | Suites | Key purpose | API | Output |
| --- | --- | --- | --- | --- | --- |
| `AUTH_ONLY` | CMAC | `AES_256_CMAC`, `SM4_CMAC` | `authenticate_verify` | `authenticate`, `verify` | Detached, versioned 16-byte authenticator |
| `ENCRYPT_ONLY` | CTR | `AES_256_CTR`, `SM4_CTR` | `encrypt_decrypt` | `encrypt`, `decrypt` | Envelope with 16-byte initial counter and no tag |
| `AUTH_ENCRYPT` | GCM | `AES_256_GCM`, `SM4_GCM` | `encrypt_decrypt` | `encrypt`, `decrypt` | Envelope with 12-byte nonce, 16-byte tag, and AAD hash |

CTR deliberately rejects `aad_b64`: it cannot authenticate AAD or detect
ciphertext modification. Use GCM whenever both secrecy and integrity are
required. CMAC never encrypts or transforms the message.

The CMAC input includes a canonical domain prefix, format version, suite ID,
tenant ID, key ID, key version, policy version, message length, and the
message. A tag therefore cannot be moved to another tenant, key, or policy
version.

## Create keys

Encryption key:

```json
{
  "tenant_id": "t-default",
  "key_id": "orders-ctr",
  "name": "Orders CTR",
  "purpose": "encrypt_decrypt",
  "policy_id": "default-v1",
  "suite_id": "AES_256_CTR"
}
```

Authentication key:

```json
{
  "tenant_id": "t-default",
  "key_id": "orders-cmac",
  "name": "Orders CMAC",
  "purpose": "authenticate_verify",
  "policy_id": "default-v1",
  "suite_id": "AES_256_CMAC"
}
```

## Authenticate and verify

`POST /ui/api/v1/crypto/authenticate` with scope `crypto:authenticate`:

```json
{
  "tenant_id": "t-default",
  "key_id": "orders-cmac",
  "message": "b3JkZXItMTIz"
}
```

The response contains a detached authenticator:

```json
{
  "authenticator": {
    "version": 1,
    "suite_id": "AES_256_CMAC",
    "service_type": "AUTH_ONLY",
    "key_id": "orders-cmac",
    "key_version": 1,
    "policy_version": 1,
    "tag": "<base64>"
  }
}
```

`POST /ui/api/v1/crypto/verify` with scope `crypto:verify` accepts the same
base64 message and authenticator object. It returns HTTP 200 with
`{"valid":true}` or `{"valid":false}`. A mismatch is a normal verification
result, not a transport error.

## Operational invariants

- A key's suite and purpose are immutable.
- `service_type` is derived from the immutable suite and is never accepted as
  an independently configurable value.
- Policy loading rejects any suite whose algorithm, mode, service type, nonce
  strategy, MAC, or composition differs from the built-in catalog.
- Deprecated suites may decrypt or verify historical material but cannot
  create new ciphertext or authenticators.
- A GCM/CTR leased nonce range is persisted before use and is never recycled.
- CTR messages are bounded far below `2^32` cipher blocks, so the block counter
  cannot carry into the leased 96-bit prefix.
- Destroyed keys and key versions cannot decrypt or verify.
