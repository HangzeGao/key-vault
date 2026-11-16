package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/commissioning"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"gopkg.in/yaml.v3"
)

func TestStageDeviceBoundInstallation(t *testing.T) {
	receiver, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := ccsds.MissionSecurityProfile{FormatVersion: 3, MissionID: "mission", TenantID: "tenant",
		TC: ccsds.MissionTCProfile{CurrentSPI: 4097, RecoverySPI: 28673, SecurityEpoch: 1,
			CurrentRootVersion: 1, NextRootVersion: 2, RecoveryRootVersion: 1,
			NoncePrefixHex: "000000000000", RecoveryNoncePrefixHex: "000000000001"}}
	digest, err := profile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	device, txn, closure := [32]byte{1}, [32]byte{2}, [32]byte{3}
	recipient := sha256.Sum256(receiver.PublicKey().Bytes())
	binding := commissioning.Binding{Purpose: commissioning.GroundRoots, ProfileDigest: digest,
		DeviceID: device, RecipientKeyID: recipient, Transaction: txn}
	roots := append(bytes.Repeat([]byte{0x41}, 16), bytes.Repeat([]byte{0x42}, 16)...)
	roots = append(roots, bytes.Repeat([]byte{0x43}, 16)...)
	envelope, err := commissioning.Seal(binding, receiver.PublicKey(), issuer, roots)
	if err != nil {
		t.Fatal(err)
	}
	envelopeDigest := sha256.Sum256(bytes.Join([][]byte{envelope.Enc, envelope.Ciphertext, envelope.Signature}, nil))
	anchorName := [34]byte{0, 11, 9}
	message := bytes.Join([][]byte{[]byte("TC-GROUND-INSTALL-V2\x00TC-ROOT-ENVELOPE-V1\x00\x02"),
		digest[:], device[:], recipient[:], txn[:], envelopeDigest[:], closure[:], anchorName[:]}, nil)
	now := time.Unix(500, 0)
	expires := now.Unix() + 100
	signature := ed25519.Sign(private, binary.BigEndian.AppendUint64(message, uint64(expires)))
	dir := t.TempDir()
	writeYAML := func(name string, document any) string {
		t.Helper()
		path := filepath.Join(dir, name)
		raw, err := yaml.Marshal(document)
		if err == nil {
			err = os.WriteFile(path, raw, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	trustPath := writeYAML("trust.yaml", enrollmentDocument{Version: 2, Node: "node", Tenant: "tenant",
		DeviceID: hex.EncodeToString(device[:]), RecipientID: hex.EncodeToString(recipient[:]), ImportHandle: 0x81000002,
		ImportName: hex.EncodeToString(make([]byte, 34)), StorageName: hex.EncodeToString(make([]byte, 34)),
		AnchorIndex: 0x01500020, AnchorName: hex.EncodeToString(anchorName[:]),
		Issuer: hex.EncodeToString(elliptic.Marshal(elliptic.P256(), issuer.X, issuer.Y)), Authority: hex.EncodeToString(authority)})
	trustData, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	wire := envelopeDocument{Version: 1, Enc: hex.EncodeToString(envelope.Enc),
		Ciphertext: hex.EncodeToString(envelope.Ciphertext), Signature: hex.EncodeToString(envelope.Signature)}
	packagePath := writeYAML("package.yaml", wire)
	approvalPath := writeYAML("approval.yaml", authorizationDocument{Version: 2, Transaction: hex.EncodeToString(txn[:]),
		ClosureDigest: hex.EncodeToString(closure[:]), ExpiresUnix: expires, Signature: hex.EncodeToString(signature)})
	request, err := loadInstallRequest(bytes.NewReader(trustData), packagePath, approvalPath, digest, now)
	if err != nil {
		t.Fatal(err)
	}
	associations, err := profile.Associations(provisionIDs(profile.TenantID, 1, 2), 1)
	if err != nil {
		t.Fatal(err)
	}
	keys := &installationTestKeys{material: make(map[string][]byte)}
	err = request.authorized.Import(receiver, request.issuer, func(plain []byte) error {
		payload, err := prepareInstallation(context.Background(), associations, plain, nil, keys)
		if err != nil {
			return err
		}
		var sealed [3]ccsds.StagedAssociation
		if !json.Valid(payload) || json.Unmarshal(payload, &sealed) != nil || len(keys.material) != len(sealed) ||
			sealed[0].VersionID == sealed[1].VersionID || sealed[2].Association.Direction != ccsds.DirectionTCRecoveryTx {
			t.Fatal("invalid staged installation")
		}
		for i, expected := range []byte{0x41, 0x43, 0x42} {
			if !bytes.Equal(keys.material[sealed[i].VersionID], bytes.Repeat([]byte{expected}, 16)) {
				t.Fatal("incorrect Current, Next, or Recovery material")
			}
		}
		verified, err := prepareInstallation(context.Background(), associations, plain, payload, keys)
		if err != nil || !bytes.Equal(verified, payload) {
			t.Fatalf("valid candidate rejected: %v", err)
		}
		keys.material[sealed[1].VersionID][0] ^= 1
		if _, err := prepareInstallation(context.Background(), associations, plain, payload, keys); err == nil {
			t.Fatal("resealed wrong root accepted")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstallRequest(bytes.NewReader(trustData), packagePath, approvalPath, digest, time.Unix(expires, 0)); err == nil {
		t.Fatal("expired approval accepted")
	}
	wire.Ciphertext = "00" + wire.Ciphertext
	writeYAML("package.yaml", wire)
	if _, err := loadInstallRequest(bytes.NewReader(trustData), packagePath, approvalPath, digest, now); err == nil {
		t.Fatal("changed package accepted")
	}
	if err := os.WriteFile(packagePath, []byte("format_version: 1\nformat_version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstallRequest(bytes.NewReader(trustData), packagePath, approvalPath, digest, now); err == nil {
		t.Fatal("duplicate document field accepted")
	}
}

type installationTestKeys struct{ material map[string][]byte }

func (k *installationTestKeys) SealExternalKey(_ context.Context, _ suite.ID, id string, root []byte) (*keyresolver.Material, error) {
	k.material[id] = bytes.Clone(root)
	return &keyresolver.Material{SealedMaterial: []byte(id)}, nil
}

func (k *installationTestKeys) UnsealKey(_ context.Context, sealed []byte, id string) ([]byte, error) {
	if string(sealed) != id {
		return nil, errors.New("sealed object context mismatch")
	}
	return bytes.Clone(k.material[id]), nil
}
