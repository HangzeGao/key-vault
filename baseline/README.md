# Key Vault ground and flight security baseline

This repository implements one strict pre-production contract:

- complete-frame CCSDS TC protection on the ground and symmetric TC unprotection in the embedded C module;
- authenticated raw downlink decryption using 8 dedicated SM4 KEKs and 1024-DEK Current/Previous batches;
- direct TPM sealing of TC roots and the downlink KEK set, without CRK/SWK compatibility layers;
- separate Data and Ops planes with bearer-token scopes;
- a release gate requiring Go and flight-C tests, 95% coverage, frontend tests/build, ARMv7 checks, and ground-to-flight vectors.

AOS framing is intentionally not implemented until the mission format freezes. Its future adapter must wrap the existing raw-downlink contract and may not create a second key lifecycle.

## Start here

- [Downlink key user manual](docs/DOWNLINK_KEY_USER_MANUAL.md)
- [CCSDS link security contract](docs/CCSDS_LINK_SECURITY.md)
- [TC ground/flight architecture](docs/TC_GROUND_FLIGHT_ARCHITECTURE.md)
- [Cryptographic test design](docs/CRYPTOGRAPHIC_TEST_DESIGN.md)
- [Example Mission Security Profile](examples/mission-security-profile.example.yaml)
- [Raw downlink hardware simulator](examples/downlink-hardware-simulator/README.md)

## Development

```bash
go test ./...
make release-gate
```

The database accepts schema version 3 only. Because the system is not in production, obsolete databases are deliberately rejected and must be reprovisioned from the controlled Mission Security Profile.
