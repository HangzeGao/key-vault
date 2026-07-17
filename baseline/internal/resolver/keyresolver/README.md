# Key Resolver

The resolver is the only application path to CRK-backed DEK wrap/unwrap and short-lived DEK leases. Data-plane handlers must not call TPM providers directly. CRK envelope replacement is synchronized; plaintext leases must be zeroized by consumers immediately after use.
