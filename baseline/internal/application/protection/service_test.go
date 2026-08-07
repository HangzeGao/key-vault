package protection

import (
	"bytes"
	"context"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

type testStore struct {
	key *models.Key
	kv  *models.KeyVersion
}

func (s *testStore) GetKey(context.Context, string, string) (*models.Key, error) { return s.key, nil }
func (s *testStore) GetKeyVersionByNo(context.Context, string, uint32) (*models.KeyVersion, error) {
	return s.kv, nil
}

type testLeaser struct{ key []byte }

func (l testLeaser) IssueDEKLease(_ context.Context, keyVersionID, keyID string, version uint32,
	suiteID suite.ID, tenantID, purpose, nodeID string) (*keyresolver.DEKLease, error) {
	return &keyresolver.DEKLease{
		KeyVersionID: keyVersionID, KeyID: keyID, KeyVersion: version, SuiteID: suiteID,
		TenantID: tenantID, Purpose: purpose, NodeID: nodeID, DEK: append([]byte(nil), l.key...),
	}, nil
}

func TestProtectionRoundTripAllServiceTypes(t *testing.T) {
	tests := []struct {
		name    string
		suiteID suite.ID
		purpose string
	}{
		{"gcm", suite.AES256GCM, "encrypt_decrypt"},
		{"ctr", suite.AES256CTR, "encrypt_decrypt"},
		{"cmac", suite.AES256CMAC, "authenticate_verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := policy.NewEngine()
			if err := policies.Load(policy.DefaultPolicy()); err != nil {
				t.Fatal(err)
			}
			store := &testStore{
				key: &models.Key{ID: "key-1", TenantID: "tenant-1", Purpose: tt.purpose, UsageScope: models.KeyUsageProtocol, PolicyID: "default-v1", SuiteID: tt.suiteID.String(), Status: "ACTIVE"},
				kv:  &models.KeyVersion{ID: "kv-1", KeyID: "key-1", VersionNo: 1, SuiteID: tt.suiteID.String(), Status: "ACTIVE"},
			}
			key := bytes.Repeat([]byte{0x42}, tt.suiteID.KeyBytes())
			core := New(store, testLeaser{key: key}, policies, 4096)
			input := []byte("payload")
			req := ProtectRequest{
				TenantID: "tenant-1", KeyID: "key-1", UsageScope: models.KeyUsageProtocol,
				KeyVersion: 1, PolicyVersion: 1, Data: input, NodeID: "node-1",
			}
			switch tt.suiteID.ServiceType() {
			case suite.ServiceAuthOnly:
				req.AuthenticationInput = []byte("header-and-payload")
			case suite.ServiceEncryptOnly:
				req.Nonce = bytes.Repeat([]byte{0x11}, 16)
			case suite.ServiceAuthEncrypt:
				req.Nonce = bytes.Repeat([]byte{0x11}, 12)
				req.AAD = append([]byte("header"), req.Nonce...)
			}
			protected, err := core.Protect(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			open := UnprotectRequest{
				TenantID: "tenant-1", KeyID: "key-1", UsageScope: models.KeyUsageProtocol, KeyVersion: 1, PolicyVersion: 1,
				Data: protected.Data, Nonce: protected.Nonce, Tag: protected.Tag, NodeID: "node-1",
			}
			switch tt.suiteID.ServiceType() {
			case suite.ServiceAuthOnly:
				open.AuthenticationInput = req.AuthenticationInput
			case suite.ServiceAuthEncrypt:
				open.AAD = req.AAD
			}
			plain, err := core.Unprotect(context.Background(), open)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain.Data, input) {
				t.Fatalf("round trip = %x, want %x", plain.Data, input)
			}
		})
	}
}

func TestUsageScopeMatchingFailsClosed(t *testing.T) {
	if usageScopeMatches("", models.KeyUsageGeneric) || usageScopeMatches(models.KeyUsageGeneric, "") {
		t.Fatal("empty usage scope must not be inferred")
	}
	if !usageScopeMatches(models.KeyUsageProtocol, models.KeyUsageProtocol) {
		t.Fatal("identical explicit usage scopes should match")
	}
}
