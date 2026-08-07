---
status: accepted
---

# ADR 0006: Use a dedicated authenticated TC profile only for root recovery

Ordinary TC remains the fixed confidentiality-only CTR profile from ADR 0005. Root recovery instead uses a dedicated SPI-bound Recovery TC Profile with AES-256-GCM or SM4-GCM, a full 16-byte tag, an independent Recovery Root, and exactly one allowed Root Recovery Transaction. Tag presence is never optional or inferred from decrypted command content: SPI selects the complete frame contract before decryption. This deliberately introduces a second strict TC profile rather than weakening the ordinary profile with an optional-tag branch.

The Recovery TC frame retains the confirmed six-byte security header `SPI[2] || IV_COUNTER[4]`; its GCM tag is a 16-byte security trailer placed before FECF. A Recovery SPI cannot execute ordinary commands, an ordinary SPI cannot execute recovery, and invalid authentication never advances replay or root state. Recovery may replace only an inactive Operational Root; the independent Recovery Root is immutable over this channel. No flight-to-ground key download exists.

This decision supersedes ADR 0005 only where ADR 0005 says all TC frames have no tag or that flight contains no GCM. Its Ordinary TC wire layout and confidentiality limitations remain unchanged.
