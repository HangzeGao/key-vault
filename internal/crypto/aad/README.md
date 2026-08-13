# Internal AAD

This package canonicalizes system-owned TPM sealed-object context as ordered TLV: purpose, object identity, node, storage name, baseline digest, and policy digest. Protocol AAD is owned by each protocol module and does not use this encoder.
