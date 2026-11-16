package confirmation

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
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/commissioning"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestIndependentConfirmationVector(t *testing.T) {
	transcript := Transcript{[32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{4}, [32]byte{5}, [32]byte{6}}
	encoded, err := transcript.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	current, recovery := bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)
	for direction, want := range map[byte]string{
		groundDirection: "3e5fe9acfde8e52dae20fe21b9c00898e8d8fb0e56f15e92ffe14e1da5cb4fbc",
		flightDirection: "880ad99d9180e7e937022f7655f261f40c885d4c0827f0d016d492b9885c015d",
	} {
		proof, err := makeProof(encoded, direction, current, recovery)
		if err != nil || hex.EncodeToString(proof[:]) != want {
			t.Fatalf("confirmation vector mismatch for direction %d: %v", direction, err)
		}
	}
	transcript.FlightChallenge = transcript.GroundChallenge
	if _, err := transcript.MarshalBinary(); !errors.Is(err, ErrConfirmation) {
		t.Fatal("reflected challenge accepted")
	}
	transcript.FlightChallenge = [32]byte{}
	if _, err := transcript.MarshalBinary(); !errors.Is(err, ErrConfirmation) {
		t.Fatal("missing challenge accepted")
	}
	if _, err := makeProof(encoded, flightDirection, current, current); !errors.Is(err, ErrConfirmation) {
		t.Fatal("identical roots accepted")
	}
}

type testAnchor [32]byte

func (a testAnchor) ReadCommissioningAnchor(context.Context, provider.RegisteredCommissioningAnchor) ([32]byte, error) {
	return a, nil
}

type testStage []byte

func (s testStage) ReadAnchoredGroundCommissioning(context.Context, string, [32]byte, [32]byte, [32]byte) ([]byte, error) {
	return s, nil
}

type failingUnsealer struct{}

func (failingUnsealer) UnsealKey(context.Context, []byte, string) ([]byte, error) {
	return nil, errors.New("unseal failed")
}

func authorizeFixture(t *testing.T, transcript Transcript, roots []byte, name [34]byte) *commissioning.AuthorizedGroundInstall {
	t.Helper()
	recipient, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := commissioning.Binding{Purpose: commissioning.GroundRoots, Transaction: transcript.Transaction, ProfileDigest: transcript.Profile,
		DeviceID: transcript.Ground, RecipientKeyID: sha256.Sum256(recipient.PublicKey().Bytes())}
	envelope, err := commissioning.Seal(binding, recipient.PublicKey(), issuer, roots)
	if err != nil {
		t.Fatal(err)
	}
	auth := commissioning.GroundAuthorization{ClosureDigest: [32]byte{7}, AnchorName: name, ExpiresUnix: 3600}
	packageDigest := sha256.Sum256(bytes.Join([][]byte{envelope.Enc, envelope.Ciphertext, envelope.Signature}, nil))
	message := bytes.Join([][]byte{[]byte("TC-GROUND-INSTALL-V2\x00TC-ROOT-ENVELOPE-V1\x00\x02"),
		binding.ProfileDigest[:], binding.DeviceID[:], binding.RecipientKeyID[:], binding.Transaction[:],
		packageDigest[:], auth.ClosureDigest[:], name[:]}, nil)
	auth.Signature = ed25519.Sign(signingKey, binary.BigEndian.AppendUint64(message, uint64(auth.ExpiresUnix)))
	install, err := commissioning.AuthorizeGroundInstall(binding, envelope, auth, authority, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return install
}

func TestGroundFlightConfirmationAfterReopen(t *testing.T) {
	if runtime.GOOS == "windows" && os.Getenv("CC") == "" {
		t.Skip("the Linux release gate runs the host C peer and SQLite integration")
	}
	ctx := t.Context()
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "cc"
	}
	dir := t.TempDir()
	peer := filepath.Join(dir, "confirmation-peer")
	cRoot := filepath.Join("..", "..", "..", "embedded", "tc_security")
	args := []string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + filepath.Join(cRoot, "include"),
		"-I" + filepath.Join(cRoot, "src"),
		filepath.Join(cRoot, "src", "kdf.c"), filepath.Join(cRoot, "src", "sm4.c"), filepath.Join(cRoot, "tests", "confirmation_peer.c"), "-o", peer}
	if output, err := exec.CommandContext(ctx, compiler, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile C peer: %v\n%s", err, output)
	}
	profile := ccsds.MissionSecurityProfile{FormatVersion: 3, MissionID: "mission", TenantID: "tenant",
		TC: ccsds.MissionTCProfile{CurrentSPI: 1, RecoverySPI: 7, SecurityEpoch: 1,
			CurrentRootVersion: 1, NextRootVersion: 2, RecoveryRootVersion: 1,
			NoncePrefixHex: "000000000000", RecoveryNoncePrefixHex: "000000000001"}}
	digest, err := profile.Digest()
	if err != nil {
		t.Fatal(err)
	}
	transcript := Transcript{[32]byte{1}, digest, [32]byte{3}, [32]byte{4}, NewChallenge(), NewChallenge()}
	encoded, err := transcript.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	current, next, recovery := bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x33}, 16), bytes.Repeat([]byte{0x22}, 16)
	anchorRecord := provider.RegisteredCommissioningAnchor{Name: [34]byte{0, 11, 6}}
	install := authorizeFixture(t, transcript, bytes.Join([][]byte{current, recovery, next}, nil), anchorRecord.Name)
	associations, err := profile.Associations(ccsds.MissionAssociationIDs{CurrentKey: "current", NextKey: "next", RecoveryKey: "recovery", CurrentSA: "c", NextSA: "n", RecoverySA: "r"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	openKeys := func() (*provider.SoftwareProvider, *keyresolver.Resolver) {
		t.Helper()
		tpm, err := provider.NewSoftwareProvider(filepath.Join(dir, "test-seals"))
		if err != nil {
			t.Fatal(err)
		}
		keys := keyresolver.New(tpm)
		if err := keys.Init(ctx, "storage", "node", digest[:], digest[:]); err != nil {
			t.Fatal(err)
		}
		return tpm, keys
	}
	tpm, keys := openKeys()
	var staged [3]ccsds.StagedAssociation
	for index, root := range [][]byte{current, next, recovery} {
		association := associations[index]
		version := []string{"current-v1", "next-v2", "recovery-v1"}[index]
		algorithm, _ := suite.Parse(association.SuiteID)
		object, err := keys.SealExternalKey(ctx, algorithm, version, root)
		if err != nil {
			t.Fatal(err)
		}
		staged[index] = ccsds.StagedAssociation{Association: association, VersionID: version, SealedMaterial: object.SealedMaterial}
	}
	path := filepath.Join(dir, "state.db")
	store, err := securitystate.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	if err := store.EnsureTenant(ctx, profile.TenantID, "test"); err != nil {
		t.Fatal(err)
	}
	commitment, err := store.StageGroundCommissioning(ctx, profile.TenantID, transcript.Transaction, install.RecordDigest(), [32]byte{},
		func([]byte) ([]byte, error) { return json.Marshal(staged) })
	if err != nil {
		t.Fatal(err)
	}
	tpm.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = securitystate.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	tpm, keys = openKeys()
	defer tpm.Close()
	ground := GroundResponder{Stage: store, TPM: testAnchor(commitment), Keys: keys}
	invoke := func(mode string, rootA, rootB, transcript []byte, proof []byte) ([]byte, error) {
		cmd := exec.CommandContext(ctx, peer, mode)
		cmd.Stdin = bytes.NewReader(bytes.Join([][]byte{rootA, rootB, transcript, proof}, nil))
		return cmd.Output()
	}
	flightRaw, err := invoke("prove", current, recovery, encoded, nil)
	if err != nil || len(flightRaw) != len(Proof{}) {
		t.Fatalf("C flight proof: %v", err)
	}
	flight := Proof(flightRaw)
	reply, err := ground.Respond(ctx, profile.TenantID, anchorRecord, install, transcript, flight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("verify", current, recovery, encoded, reply[:]); err != nil {
		t.Fatalf("C rejected the ground response: %v", err)
	}
	for _, mutation := range []int{0, 16} {
		wrong := flight
		wrong[mutation] ^= 1
		if got, err := ground.Respond(ctx, profile.TenantID, anchorRecord, install, transcript, wrong); got != (Proof{}) || !errors.Is(err, ErrConfirmation) {
			t.Fatal("invalid root proof elicited a response")
		}
	}
	replayed := transcript
	replayed.GroundChallenge = NewChallenge()
	if _, err := ground.Respond(ctx, profile.TenantID, anchorRecord, install, replayed, flight); !errors.Is(err, ErrConfirmation) {
		t.Fatal("old flight proof accepted for a fresh challenge")
	}
	if _, err := invoke("verify", current, recovery, encoded, flight[:]); err == nil {
		t.Fatal("flight accepted reflected proof")
	}
	assertRejected := func(candidate GroundResponder, expected Transcript) {
		t.Helper()
		if reply, err := candidate.Respond(ctx, profile.TenantID, anchorRecord, install, expected, flight); reply != (Proof{}) || !errors.Is(err, ErrConfirmation) {
			t.Fatal("invalid local state returned a proof")
		}
	}
	assertRejected(GroundResponder{}, transcript)
	foreign := transcript
	foreign.Ground[0] ^= 1
	assertRejected(ground, foreign)
	invalid := ground
	invalid.TPM = testAnchor{}
	assertRejected(invalid, transcript)
	invalid = ground
	invalid.Stage = testStage(`[]`)
	assertRejected(invalid, transcript)
	installed, err := store.ReadAnchoredGroundCommissioning(ctx, profile.TenantID, transcript.Transaction, install.RecordDigest(), commitment)
	if err != nil {
		t.Fatal(err)
	}
	invalid.Stage = testStage(installed)
	invalid.Keys = failingUnsealer{}
	assertRejected(invalid, transcript)
	staged[0].VersionID = "swapped"
	wrongVersion, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	invalid.Stage = testStage(wrongVersion)
	assertRejected(invalid, transcript)
	ground.TPM = testAnchor([32]byte{9})
	if _, err := ground.Respond(ctx, profile.TenantID, anchorRecord, install, transcript, flight); !errors.Is(err, ErrConfirmation) {
		t.Fatal("unbound installation proved possession")
	}
	if _, err := store.ReadMissionProfileDigest(ctx, profile.TenantID); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatal("confirmation published a live mission")
	}
}
