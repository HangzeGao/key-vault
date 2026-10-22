# Development

The service has no browser frontend or Node.js toolchain. Use Go for the
service and `kvltctl`, and Make for the flight modules.

Run `make release-gate` before delivery. The gate covers all Go packages, the
operations CLI, flight-C coverage, ARMv7 builds and differential tests, and
the TC ground-to-flight end-to-end vectors. It also runs `make downlink-gate`
for the fixed AES-256-ECB data field, with independent C/Go coverage, sanitizer,
fuzz, and actual native/ARMv7 C ciphertext consumed by Go.
