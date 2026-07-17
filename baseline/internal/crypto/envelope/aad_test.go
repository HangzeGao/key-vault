package envelope

import "fmt"

type testCallerAAD struct {
	TenantID   string
	KeyID      string
	KeyVersion uint32
	Purpose    string
	SuiteID    uint16
	ResourceID string
}

func (c testCallerAAD) Canonical() ([]byte, error) {
	return []byte(fmt.Sprintf("%s|%s|%d|%s|%d|%s",
		c.TenantID, c.KeyID, c.KeyVersion, c.Purpose, c.SuiteID, c.ResourceID)), nil
}
