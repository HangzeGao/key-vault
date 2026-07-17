# Internal AAD

This package canonicalizes system-owned CRK context as ordered TLV: cluster, node, plane role, CRK version, NRWK name, baseline digest, and policy digest. It is not the data-plane business AAD helper; callers use `sdk/aad` and submit the resulting bytes as `aad_b64`.
