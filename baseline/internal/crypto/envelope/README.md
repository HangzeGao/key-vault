# Envelope

Immutable `CoreEnvelope` parsing, AEAD open/seal, JSON format detection, and tenant profile rendering live here. Caller `aad_b64` is opaque input to AEAD and is never reconstructed from a profile. External envelope formats are limited to JSON adapters; the internal canonical encoding is not registered as a client-facing format. Add formats through the registry and keep parsing errors generic at API boundaries.
