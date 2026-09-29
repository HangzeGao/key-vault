//go:build !downlink

package securitystate

// The TC-only schema has no downlink table.
func downlinkSchemaStatements() []string { return nil }

func schemaModeMatches(existingDownlinkTables int) bool { return existingDownlinkTables == 0 }
