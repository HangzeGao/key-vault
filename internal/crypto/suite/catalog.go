// Package suite defines the system's supported symmetric protection suites.
//
// It is the single source of truth for the mapping between a security service,
// its algorithm, allowed operations, key purpose, nonce size, and tag size.
// Callers select a suite; they do not assemble an arbitrary combination.
package suite

import "fmt"

// ServiceType is the security contract provided by a suite.
type ServiceType string

const (
	ServiceAuthOnly    ServiceType = "AUTH_ONLY"
	ServiceEncryptOnly ServiceType = "ENCRYPT_ONLY"
	ServiceAuthEncrypt ServiceType = "AUTH_ENCRYPT"
)

// Operation is an externally visible cryptographic operation.
type Operation string

const (
	OperationEncrypt      Operation = "encrypt"
	OperationDecrypt      Operation = "decrypt"
	OperationAuthenticate Operation = "authenticate"
	OperationVerify       Operation = "verify"
)

// ID is stable and is part of the protection-envelope wire format. Retired
// values must never be reused.
type ID uint16

const (
	AES256GCM  ID = 0x0001
	SM4GCM     ID = 0x0002
	AES256CTR  ID = 0x0011
	SM4CTR     ID = 0x0012
	SM4HCTR    ID = 0x0013
	AES256CMAC ID = 0x0021
	SM4CMAC    ID = 0x0022
)

// Descriptor contains immutable suite semantics.
type Descriptor struct {
	ID             ID
	Name           string
	Algorithm      string
	KeyBits        int
	WorkingKeyBits int
	Mode           string
	ServiceType    ServiceType
	KeyPurpose     string
	NonceStrategy  string
	NonceBytes     int
	TagBytes       int
	MAC            string
	Composition    string
}

var catalog = [...]Descriptor{
	{ID: AES256GCM, Name: "AES_256_GCM", Algorithm: "AES", KeyBits: 256, Mode: "GCM", ServiceType: ServiceAuthEncrypt, KeyPurpose: "encrypt_decrypt", NonceStrategy: "lease_counter", NonceBytes: 12, TagBytes: 16},
	{ID: SM4GCM, Name: "SM4_GCM", Algorithm: "SM4", KeyBits: 128, Mode: "GCM", ServiceType: ServiceAuthEncrypt, KeyPurpose: "encrypt_decrypt", NonceStrategy: "lease_counter", NonceBytes: 12, TagBytes: 16},
	{ID: AES256CTR, Name: "AES_256_CTR", Algorithm: "AES", KeyBits: 256, Mode: "CTR", ServiceType: ServiceEncryptOnly, KeyPurpose: "encrypt_decrypt", NonceStrategy: "lease_counter", NonceBytes: 16},
	{ID: SM4CTR, Name: "SM4_CTR", Algorithm: "SM4", KeyBits: 128, Mode: "CTR", ServiceType: ServiceEncryptOnly, KeyPurpose: "encrypt_decrypt", NonceStrategy: "lease_counter", NonceBytes: 16},
	{ID: SM4HCTR, Name: "SM4_HCTR", Algorithm: "SM4", KeyBits: 128, WorkingKeyBits: 256, Mode: "HCTR", ServiceType: ServiceEncryptOnly, KeyPurpose: "encrypt_decrypt", NonceStrategy: "protocol_tweak", NonceBytes: 16},
	{ID: AES256CMAC, Name: "AES_256_CMAC", Algorithm: "AES", KeyBits: 256, Mode: "CMAC", ServiceType: ServiceAuthOnly, KeyPurpose: "authenticate_verify", NonceStrategy: "none", TagBytes: 16, MAC: "CMAC", Composition: "MAC_ONLY"},
	{ID: SM4CMAC, Name: "SM4_CMAC", Algorithm: "SM4", KeyBits: 128, Mode: "CMAC", ServiceType: ServiceAuthOnly, KeyPurpose: "authenticate_verify", NonceStrategy: "none", TagBytes: 16, MAC: "CMAC", Composition: "MAC_ONLY"},
}

// All returns a copy of the complete suite catalog.
func All() []Descriptor {
	out := make([]Descriptor, len(catalog))
	copy(out, catalog[:])
	return out
}

// Parse resolves a suite name.
func Parse(name string) (ID, error) {
	for _, descriptor := range catalog {
		if descriptor.Name == name {
			return descriptor.ID, nil
		}
	}
	return 0, fmt.Errorf("suite: unknown suite %q", name)
}

// Describe resolves immutable metadata for an ID.
func Describe(id ID) (Descriptor, error) {
	for _, descriptor := range catalog {
		if descriptor.ID == id {
			return descriptor, nil
		}
	}
	return Descriptor{}, fmt.Errorf("suite: unknown id 0x%04X", uint16(id))
}

func (id ID) String() string {
	descriptor, err := Describe(id)
	if err != nil {
		return fmt.Sprintf("SUITE_0x%04X", uint16(id))
	}
	return descriptor.Name
}

func (id ID) KeyBits() int {
	descriptor, _ := Describe(id)
	return descriptor.KeyBits
}

func (id ID) KeyBytes() int { return id.KeyBits() / 8 }

// WorkingKeyBytes is the key material consumed by the primitive after any
// protocol-owned derivation. It differs from KeyBytes only for constructions
// such as HCTR that use independent block-cipher and universal-hash keys.
func (id ID) WorkingKeyBytes() int {
	descriptor, _ := Describe(id)
	if descriptor.WorkingKeyBits != 0 {
		return descriptor.WorkingKeyBits / 8
	}
	return descriptor.KeyBits / 8
}

func (id ID) NonceLen() int {
	descriptor, _ := Describe(id)
	return descriptor.NonceBytes
}

func (id ID) TagLen() int {
	descriptor, _ := Describe(id)
	return descriptor.TagBytes
}

func (id ID) ServiceType() ServiceType {
	descriptor, _ := Describe(id)
	return descriptor.ServiceType
}

func (id ID) KeyPurpose() string {
	descriptor, _ := Describe(id)
	return descriptor.KeyPurpose
}

func (id ID) Supports(operation Operation) bool {
	switch id.ServiceType() {
	case ServiceAuthOnly:
		return operation == OperationAuthenticate || operation == OperationVerify
	case ServiceEncryptOnly, ServiceAuthEncrypt:
		return operation == OperationEncrypt || operation == OperationDecrypt
	default:
		return false
	}
}

func (id ID) AuthenticatesAAD() bool {
	return id.ServiceType() == ServiceAuthEncrypt
}

func (id ID) CiphertextLen(plaintextLen int) int { return plaintextLen }
