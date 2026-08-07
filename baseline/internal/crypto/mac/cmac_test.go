package mac

import (
	"encoding/hex"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

func TestAES256CMACRoundTripAndMetadataBinding(t *testing.T) {
	key := make([]byte, 32)
	meta := Metadata{
		Version:       TagVersion,
		SuiteID:       suite.AES256CMAC,
		TenantID:      "tenant-1",
		KeyID:         "auth-key",
		KeyVersion:    3,
		PolicyVersion: 7,
	}
	tag, err := Compute(meta.SuiteID, key, meta, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) != 16 {
		t.Fatalf("tag length = %d, want 16", len(tag))
	}
	ok, err := Verify(meta.SuiteID, key, meta, []byte("message"), tag)
	if err != nil || !ok {
		t.Fatalf("Verify() = %v, %v", ok, err)
	}
	meta.KeyVersion++
	ok, err = Verify(meta.SuiteID, key, meta, []byte("message"), tag)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tag verified after metadata was changed")
	}
	meta.KeyVersion--
	meta.TenantID = "tenant-2"
	ok, err = Verify(meta.SuiteID, key, meta, []byte("message"), tag)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tag verified in a different tenant")
	}
}

func TestAESCMACCanonicalFormatVector(t *testing.T) {
	// Use the AES-256 key from the NIST SP 800-38B vectors. The expected value
	// includes this package's domain-separated metadata prefix and is therefore
	// a stable vector for the complete detached-authenticator format.
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	meta := Metadata{Version: TagVersion, SuiteID: suite.AES256CMAC, TenantID: "t", KeyID: "k", KeyVersion: 1, PolicyVersion: 1}
	tag, err := Compute(meta.SuiteID, key, meta, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tag); got != "931860d22f5d61f5ec0643fe17d0b2bf" {
		t.Fatalf("tag = %s", got)
	}
}

func TestRawCMACDoesNotAddEnvelopeMetadata(t *testing.T) {
	key := make([]byte, 32)
	input := []byte("protocol-canonical-input")
	tag, err := ComputeRaw(suite.AES256CMAC, key, input)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := VerifyRaw(suite.AES256CMAC, key, input, tag)
	if err != nil || !valid {
		t.Fatalf("VerifyRaw() = %v, %v", valid, err)
	}
	valid, err = VerifyRaw(suite.AES256CMAC, key, []byte("changed"), tag)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("raw CMAC verified changed protocol input")
	}
}
