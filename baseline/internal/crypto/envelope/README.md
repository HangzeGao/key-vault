# Envelope

Immutable `CoreEnvelope` parsing, AEAD open/seal, format detection, and tenant profile rendering live here. Caller `aad_b64` is opaque input to AEAD and is never reconstructed from a profile. Add formats through the registry and keep parsing errors generic at API boundaries.
