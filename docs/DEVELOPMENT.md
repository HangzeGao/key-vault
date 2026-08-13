# Development

The service has no browser frontend or Node.js toolchain. Use Go for the
service and `kvltctl`, and CMake/CTest for the flight module.

Run `make release-gate` before delivery. The gate covers all Go packages, the
operations CLI, flight-C coverage, ARMv7 builds and differential tests, and
the TC/downlink end-to-end vectors.
