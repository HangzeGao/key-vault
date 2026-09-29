# Key Vault ground and flight security baseline

This repository implements one strict pre-production contract:

- complete-frame CCSDS TC protection on the ground and symmetric TC unprotection in the embedded C module;
- optional authenticated raw downlink decryption using 8 dedicated SM4 KEKs and 1024-DEK Current/Previous batches;
- direct TPM sealing of TC roots and, in the downlink build, the dedicated KEK set;
- separate Data and Ops planes with exact source-IP enforcement, SHA-256 bearer-token verifiers, and fixed scopes;
- a release gate requiring Go and flight-C tests, 95% coverage, operations CLI tests, ARMv7 checks, and ground-to-flight vectors.
- independent open-source SM4/CMAC/GCM/HCTR/KDF vectors consumed by both ground Go and flight C, anchored by RFC 8998 SM4-GCM.

Operations are intentionally browser-free. Use the loopback-only `kvltctl`
interface documented in [docs/OPERATIONS_CLI.md](docs/OPERATIONS_CLI.md).

AOS frame parsing is not yet implemented. The optional downlink build currently accepts only the fixed RAW hardware package; an AOS adapter must wrap that contract without a second key lifecycle.

The default Go build is **TC-only**: it has no downlink route, KEK/DEK initialization, downlink table, or downlink CLI. Build and provision a mission with downlink using `-tags downlink` consistently. The two build variants reject each other's database; do not switch variants against an existing state database.

## Start here

- [Downlink key user manual](docs/DOWNLINK_KEY_USER_MANUAL.md)
- [Access-control user manual](docs/ACCESS_CONTROL_USER_MANUAL.md)
- [Access-control test design](docs/ACCESS_CONTROL_TEST_DESIGN.md)
- [CCSDS link security contract](docs/CCSDS_LINK_SECURITY.md)
- [TC ground/flight architecture](docs/TC_GROUND_FLIGHT_ARCHITECTURE.md)
- [Cryptographic test design](docs/CRYPTOGRAPHIC_TEST_DESIGN.md)
- [TC-only Mission Security Profile](examples/mission-security-profile.example.yaml)
- [TC + downlink Mission Security Profile](examples/mission-security-profile.downlink.example.yaml)
- [Raw downlink hardware simulator](examples/downlink-hardware-simulator/README.md)

## Development

```bash
go test ./...
go test -tags downlink ./...
make release-gate
```

The only supported service launcher requires an explicit configuration and
never creates credentials or TPM fallbacks:

```bash
bash start.sh serve /etc/key-vault/config.yaml
```

For a mission that uses hardware downlink, set `KVLT_ENABLE_DOWNLINK=1` for both `start.sh provision-ccsds` and `start.sh serve`; build `downlink-keyctl` with `go build -tags downlink ./cmd/downlink-keyctl`. The default (`0`) needs no KEK material and rejects a `downlink:` profile section.

Use [config.production.example.yaml](config.production.example.yaml) as the
field reference. Install the service under a dedicated non-root account; do not
run it through the removed Docker/Compose development path.

The database accepts schema version 3 only. Because the system is not in production, obsolete databases are deliberately rejected and must be reprovisioned from the controlled Mission Security Profile.
