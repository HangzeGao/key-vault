# Key Resolver

The resolver is the only application path to directly TPM-sealed TC protocol roots. There is no intermediate CRK or software wrapping key. Data-plane handlers do not call TPM providers directly, and callers zeroize each returned key after one operation.
