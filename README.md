# Key Vault ground and flight security baseline

This repository implements one strict pre-production contract:

- complete-frame CCSDS TC protection on the ground and symmetric TC unprotection in the embedded C module;
- authenticated raw downlink decryption using 8 dedicated SM4 KEKs and 1024-DEK Current/Previous batches;
- direct TPM sealing of TC roots and the downlink KEK set, without CRK/SWK compatibility layers;
- separate Data and Ops planes with exact source-IP enforcement, SHA-256 bearer-token verifiers, and fixed scopes;
- a release gate requiring Go and flight-C tests, 95% coverage, operations CLI tests, ARMv7 checks, and ground-to-flight vectors.
- independent open-source SM4/CMAC/GCM/HCTR/KDF vectors consumed by both ground Go and flight C, anchored by RFC 8998 SM4-GCM.

Operations are intentionally browser-free. Use the loopback-only `kvltctl`
interface documented in [docs/OPERATIONS_CLI.md](docs/OPERATIONS_CLI.md).

AOS framing is intentionally not implemented until the mission format freezes. Its future adapter must wrap the existing raw-downlink contract and may not create a second key lifecycle.

## Start here

- [Downlink key user manual](docs/DOWNLINK_KEY_USER_MANUAL.md)
- [Access-control user manual](docs/ACCESS_CONTROL_USER_MANUAL.md)
- [Access-control test design](docs/ACCESS_CONTROL_TEST_DESIGN.md)
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

The only supported service launcher requires an explicit configuration and
never creates credentials or TPM fallbacks:

```bash
bash start.sh serve /etc/key-vault/config.yaml
```

Use [config.production.example.yaml](config.production.example.yaml) as the
field reference. Install the service under a dedicated non-root account; do not
run it through the removed Docker/Compose development path.

The database accepts schema version 3 only. Because the system is not in production, obsolete databases are deliberately rejected and must be reprovisioned from the controlled Mission Security Profile.
