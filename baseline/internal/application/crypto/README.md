# Crypto Application Service

Encrypt/decrypt validates tenant, key state, suite policy, tenant AAD policy, envelope format allowlists, nonce allocation, and DEK lease boundaries. API errors never expose AEAD or envelope internals. Batch handlers preserve per-entry results while returning sanitized error codes and aggregate failure ratios.
