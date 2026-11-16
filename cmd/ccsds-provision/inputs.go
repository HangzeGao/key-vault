package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"github.com/kvlt/key-vault/internal/commissioning"
	"github.com/kvlt/key-vault/internal/tpm/provider"
	"gopkg.in/yaml.v3"
)

type enrollmentDocument struct {
	Version      uint16 `yaml:"format_version"`
	Node         string `yaml:"node_id"`
	Tenant       string `yaml:"tenant_id"`
	DeviceID     string `yaml:"device_id_hex"`
	RecipientID  string `yaml:"recipient_key_id_hex"`
	ImportHandle uint32 `yaml:"import_handle"`
	ImportName   string `yaml:"import_object_name_hex"`
	StorageName  string `yaml:"storage_object_name_hex"`
	AnchorIndex  uint32 `yaml:"stage_anchor_index"`
	AnchorName   string `yaml:"stage_anchor_name_hex"`
	Issuer       string `yaml:"envelope_issuer_p256_hex"`
	Authority    string `yaml:"install_authority_ed25519_hex"`
}

type envelopeDocument struct {
	Version    uint16 `yaml:"format_version"`
	Enc        string `yaml:"enc_hex"`
	Ciphertext string `yaml:"ciphertext_hex"`
	Signature  string `yaml:"signature_der_hex"`
}

type authorizationDocument struct {
	Version       uint16 `yaml:"format_version"`
	Transaction   string `yaml:"transaction_id_hex"`
	ClosureDigest string `yaml:"closure_receipt_sha256"`
	ExpiresUnix   int64  `yaml:"expires_unix"`
	Signature     string `yaml:"signature_hex"`
}

type installRequest struct {
	node, tenant string
	binding      commissioning.Binding
	issuer       *ecdsa.PublicKey
	registration provider.RegisteredImportKey
	anchor       provider.RegisteredCommissioningAnchor
	authorized   *commissioning.AuthorizedGroundInstall
}

func loadInstallRequest(enrollment io.Reader, envelopePath, authorizationPath string, digest [32]byte, now time.Time) (*installRequest, error) {
	var trust enrollmentDocument
	var wire envelopeDocument
	var approval authorizationDocument
	if decodeDocument(enrollment, &trust) != nil || trust.Version != 2 || trust.Node == "" || trust.Tenant == "" {
		return nil, errors.New("invalid commissioning enrollment")
	}
	if readDocument(envelopePath, &wire) != nil || wire.Version != 1 {
		return nil, errors.New("invalid ground envelope")
	}
	if readDocument(authorizationPath, &approval) != nil || approval.Version != 2 {
		return nil, errors.New("invalid installation authorization")
	}
	request := installRequest{
		node: trust.Node, tenant: trust.Tenant,
		binding:      commissioning.Binding{Purpose: commissioning.GroundRoots, ProfileDigest: digest},
		registration: provider.RegisteredImportKey{Handle: trust.ImportHandle},
		anchor:       provider.RegisteredCommissioningAnchor{Index: trust.AnchorIndex},
	}
	var authority [ed25519.PublicKeySize]byte
	var auth commissioning.GroundAuthorization
	var issuer [65]byte
	if !decodeHex(request.binding.DeviceID[:], trust.DeviceID) ||
		!decodeHex(request.binding.RecipientKeyID[:], trust.RecipientID) ||
		!decodeHex(request.binding.Transaction[:], approval.Transaction) ||
		!decodeHex(request.registration.ObjectName[:], trust.ImportName) ||
		!decodeHex(request.registration.StorageName[:], trust.StorageName) ||
		!decodeHex(request.anchor.Name[:], trust.AnchorName) ||
		!decodeHex(issuer[:], trust.Issuer) || !decodeHex(authority[:], trust.Authority) ||
		!decodeHex(auth.ClosureDigest[:], approval.ClosureDigest) {
		return nil, errors.New("invalid commissioning identity or signature policy")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), issuer[:])
	if x == nil {
		return nil, errors.New("invalid envelope issuer key")
	}
	request.issuer = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	request.anchor.StorageName = request.registration.StorageName
	auth.AnchorName = request.anchor.Name
	enc, encErr := hex.DecodeString(wire.Enc)
	ciphertext, cipherErr := hex.DecodeString(wire.Ciphertext)
	signature, sigErr := hex.DecodeString(wire.Signature)
	auth.Signature, _ = hex.DecodeString(approval.Signature)
	auth.ExpiresUnix = approval.ExpiresUnix
	if encErr != nil || cipherErr != nil || sigErr != nil {
		return nil, errors.New("invalid envelope encoding")
	}
	var err error
	request.authorized, err = commissioning.AuthorizeGroundInstall(request.binding,
		commissioning.Envelope{Enc: enc, Ciphertext: ciphertext, Signature: signature}, auth, authority[:], now)
	if err != nil {
		return nil, errors.New("installation authorization rejected")
	}
	return &request, nil
}

func decodeHex(dst []byte, encoded string) bool {
	if len(encoded) != hex.EncodedLen(len(dst)) {
		return false
	}
	_, err := hex.Decode(dst, []byte(encoded))
	return err == nil
}

func input(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readInput(file)
}

func readInput(reader io.Reader) ([]byte, error) {
	const limit = 16 << 10
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, errors.New("unreadable or oversized commissioning input")
	}
	return raw, nil
}

func readDocument(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return decodeDocument(file, target)
}

func decodeDocument(reader io.Reader, target any) error {
	raw, err := readInput(reader)
	if err != nil {
		return err
	}
	defer clear(raw)
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid commissioning document")
	}
	return nil
}
