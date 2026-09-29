//go:build !downlink

package features

// Downlink is a compile-time capability, not a runtime configuration switch.
const Downlink = false
