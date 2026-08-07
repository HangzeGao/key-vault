---
status: accepted
---

# Keep trusted policy versions in one shared catalog

Signed policy reload activates a validated version in a stable, shared, versioned policy catalog instead of replacing the catalog instance or overwriting its history. New key and encryption decisions use the current version, while decryption resolves the exact version recorded in the Envelope; this preserves hot-reload visibility for every caller and keeps old ciphertext decryptable under its original trusted rules.
