# Caller AAD SDK

`CanonicalJSON` implements RFC 8785/JCS. `Protobuf` accepts deterministic wire bytes, `Raw` copies arbitrary bytes, and `HTTPHeaders` canonicalizes an explicit allowlist. Encode the returned bytes as standard padded base64 in `aad_b64`; reuse exactly the same bytes for decrypt. Cross-language clients must consume `testdata/vectors.json`.
