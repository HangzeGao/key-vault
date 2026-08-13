# Raw downlink hardware simulator

This test-only command opens an exported 16417-byte DEK upload package using the public example Mission Security Profile, selects one DEK, and emits the exact JSON accepted by `POST /api/v1/downlink:unprotect`.

```bash
go run ./examples/downlink-hardware-simulator \
  -mission-profile ./examples/mission-security-profile.example.yaml \
  -dek-package ./private/upload/downlink-dek-generation.bin \
  -key-serial 17 \
  -nonce-hex 000000000000000000000001 \
  -plaintext 'example payload'
```

The nonce is mandatory and explicit. This command models the wire format, not the hardware nonce generator. Never use the example profile or a deterministic nonce in flight.
