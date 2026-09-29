//go:build !downlink

package access

func dataPlaneScopes() []string {
	return []string{"ccsds:tc:protect", "ccsds:flight-status:observe"}
}
