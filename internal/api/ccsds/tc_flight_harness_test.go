package ccsds_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/suite"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/securitystate"
)

// All material and plaintext in this harness is public TEST ONLY data. Expected
// plaintext is supplied by the caller, never decrypted a second time in Go.
var flightCommand = []byte{0x10, 0x42, 0xc0, 1, 0, 9, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0}

type flightReply struct {
	Status        string `json:"status"`
	Length        int    `json:"length"`
	Plaintext     string `json:"plaintext"`
	Cleared       bool   `json:"cleared"`
	CommitCalls   int    `json:"commit_calls"`
	Diagnostic    string `json:"diagnostic"`
	CurrentSPI    uint16 `json:"current_spi"`
	NextSPI       uint16 `json:"next_spi"`
	RecoverySPI   uint16 `json:"recovery_spi"`
	Epoch         uint32 `json:"epoch"`
	RootVersion   uint32 `json:"root_version"`
	Pending       bool   `json:"pending"`
	Paused        bool   `json:"paused"`
	ReceiveCount  uint64 `json:"receive_count"`
	ProfileDigest string `json:"profile_digest"`
}

func successPlaintext(status string, plain []byte) []byte {
	if status == "OK" || status == "EPOCH_PROMOTED" {
		return plain
	}
	return nil
}
func (r flightReply) require(t *testing.T, status string, plain []byte) {
	t.Helper()
	got, err := hex.DecodeString(r.Plaintext)
	if err != nil || r.Status != status || r.Length != len(plain) || !bytes.Equal(got, plain) ||
		(len(plain) == 0 && !r.Cleared) {
		t.Fatalf("flight status=%s length=%d cleared=%t plaintext_equal=%t; want %s length=%d", r.Status, r.Length, r.Cleared, bytes.Equal(got, plain), status, len(plain))
	}
}

type flightProcess struct {
	t       *testing.T
	cmd     *exec.Cmd
	input   io.WriteCloser
	decoder *json.Decoder
	startup flightReply
	waited  bool
	cancel  context.CancelFunc
}

func commissionFlight(t *testing.T, runner, vector, state string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, runner, vector, state, "commission").CombinedOutput(); err != nil {
		t.Fatalf("commission failed: %v %s", err, out)
	}
}
func startFlight(t *testing.T, runner, vector, state, expected string) *flightProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	cmd := exec.CommandContext(ctx, runner, vector, state, "session")
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	p := &flightProcess{t: t, cmd: cmd, input: input, decoder: json.NewDecoder(output), cancel: cancel}
	t.Cleanup(p.close)
	p.startup = p.read()
	p.startup.require(t, expected, nil)
	return p
}
func (p *flightProcess) read() flightReply {
	p.t.Helper()
	var r flightReply
	if err := p.decoder.Decode(&r); err != nil {
		p.t.Fatalf("flight reply unavailable: %v", err)
	}
	return r
}
func (p *flightProcess) write(line string) {
	p.t.Helper()
	if _, err := io.WriteString(p.input, line+"\n"); err != nil {
		p.t.Fatal(err)
	}
}
func (p *flightProcess) receive(fault string, frame []byte) flightReply {
	p.t.Helper()
	encoded := hex.EncodeToString(frame)
	if encoded == "" {
		encoded = "-"
	}
	p.write("receive " + fault + " " + encoded)
	return p.read()
}
func (p *flightProcess) reset() flightReply { p.write("reset"); return p.read() }
func (p *flightProcess) crash(fault string, frame []byte, code int) {
	p.t.Helper()
	p.write("receive " + fault + " " + hex.EncodeToString(frame))
	var r flightReply
	if err := p.decoder.Decode(&r); err != io.EOF {
		p.t.Fatalf("terminated process emitted reply or invalid transport: %v", err)
	}
	_ = p.input.Close()
	err := p.cmd.Wait()
	p.waited = true
	p.cancel()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != code {
		p.t.Fatalf("crash fault exit=%v want=%d", err, code)
	}
}
func (p *flightProcess) close() {
	if p.waited {
		return
	}
	p.waited = true
	_ = p.input.Close()
	err := p.cmd.Wait()
	p.cancel()
	if err != nil {
		p.t.Errorf("flight process exit: %v", err)
	}
}

// The ground fixture uses HTTP for ordinary TC and observation. Root Prepare
// has no HTTP route: it uses the real controlled protocol method explicitly.
// Provisioning uses the store's public methods; no scenario mutates SQL rows.
type tcFlightHarness struct {
	t                             *testing.T
	runner, vector, state, ground string
	keys                          map[string]e2eKey
	store                         *securitystate.Store
	service                       *protocol.FrameSecurity
	server                        *httptest.Server
}

func newTCFlightHarness(t *testing.T) *tcFlightHarness {
	t.Helper()
	runner := os.Getenv("TC_E2E_FLIGHT_RUNNER")
	if runner == "" {
		if os.Getenv("TC_E2E_REQUIRED") == "1" {
			t.Fatal("required flight process runner is missing")
		}
		t.Skip("flight process scenarios run in scripts/tc_process_gate.sh")
	}
	vector, err := filepath.Abs("../../../testdata/ccsds_tc_sm4_gcm_recovery.txt")
	if err != nil {
		t.Fatal(err)
	}
	values := readVector(t, vector)
	decode := func(name string) []byte {
		b, e := hex.DecodeString(values[name])
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	dir := t.TempDir()
	h := &tcFlightHarness{t: t, runner: runner, vector: vector, state: filepath.Join(dir, "flight.test-state"), ground: filepath.Join(dir, "ground.db"), keys: map[string]e2eKey{
		"current":  {root: decode("ordinary_root"), suite: suite.SM4HCTR, version: 7},
		"next":     {root: bytes.Repeat([]byte{0x77}, 16), suite: suite.SM4HCTR, version: 8},
		"recovery": {root: decode("root"), suite: suite.SM4GCM, version: 3},
	}}
	h.openGround()
	ctx := context.Background()
	if err = h.store.EnsureTenant(ctx, "tenant-1", "E2E TEST ONLY"); err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{}
	for i := range digest {
		digest[i] = 0x5a
	}
	if err = h.store.BindMissionProfile(ctx, "tenant-1", digest); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"current", "next", "recovery"} {
		k := h.keys[id]
		key := &models.Key{ID: id, TenantID: "tenant-1", Name: "E2E TEST ONLY", Purpose: "encrypt_decrypt", UsageScope: models.KeyUsageProtocol, PolicyID: "default-v1", SuiteID: k.suite.String(), CurrentVersion: k.version, Status: "ACTIVE"}
		version := &models.KeyVersion{ID: id + "-version", KeyID: id, VersionNo: k.version, SuiteID: k.suite.String(), SealedMaterial: []byte("TEST ONLY key-source substitute"), Status: "ACTIVE"}
		if err = h.store.CreateProtocolKey(ctx, key, version); err != nil {
			t.Fatal(err)
		}
		sa := protocol.SecurityAssociation{ID: id, TenantID: "tenant-1", SPI: 0x2001, Direction: protocol.DirectionTCTx, KeyID: id, KeyVersion: k.version, SecurityEpoch: 8, PolicyVersion: 1, SuiteID: k.suite.String(), State: protocol.AssociationCurrent, Parameters: protocol.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: []byte("ORDNRY")}}
		if id == "next" {
			sa.SPI++
			sa.SecurityEpoch++
			sa.State = protocol.AssociationNext
		}
		if id == "recovery" {
			sa.SPI = 0x7002
			sa.Direction = protocol.DirectionTCRecoveryTx
			sa.SecurityEpoch = 0
			sa.State = protocol.AssociationActive
			sa.Parameters.TagLength = 16
			sa.Parameters.NoncePrefix = decode("nonce_prefix")
		}
		if err = h.store.CreateAssociation(ctx, sa); err != nil {
			t.Fatal(err)
		}
	}
	commissionFlight(t, runner, vector, h.state)
	t.Cleanup(func() {
		h.server.Close()
		if err := h.store.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}
func (h *tcFlightHarness) openGround() {
	h.t.Helper()
	store, err := securitystate.Open(context.Background(), h.ground)
	if err != nil {
		h.t.Fatal(err)
	}
	service, err := protocol.New(e2eCore{keys: h.keys}, store, protocol.Options{MaxFrameLength: 1024, NodeID: "e2e-ground", TCSpacecraftID: 1})
	if err != nil {
		h.t.Fatal(err)
	}
	h.store, h.service = store, service
	h.server = httptest.NewServer(authenticatedHandler(service))
}
func (h *tcFlightHarness) restartGround() {
	h.t.Helper()
	h.server.Close()
	if err := h.store.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.openGround()
}
func (h *tcFlightHarness) post(path, token string, body any, want int) []byte {
	h.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	out, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != want {
		h.t.Fatalf("HTTP %s status=%d want=%d read=%v", path, response.StatusCode, want, err)
	}
	return out
}
func (h *tcFlightHarness) protect(plain []byte) []byte {
	h.t.Helper()
	frame := buildClearTCFrame(plain)
	// The synthetic Next mission policy permits VCID 0. The ordinary vector
	// helper uses VCID 1, which must not silently bypass this rule in a campaign.
	frame[2] &= 3
	rewriteFECF(frame)
	raw := h.post("/api/v1/tc:protect", testDataToken(), map[string]string{"frame": base64.StdEncoding.EncodeToString(frame)}, http.StatusOK)
	var out struct {
		ProtectedFrame string `json:"protected_frame"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatal(err)
	}
	frame, err := base64.StdEncoding.DecodeString(out.ProtectedFrame)
	if err != nil {
		h.t.Fatal(err)
	}
	return frame
}
func (h *tcFlightHarness) prepare() []byte {
	h.t.Helper()
	cmd := protocol.RootPrepareCommand{TransactionID: 9, ExpectedCurrentRootVersion: 7, NewRootVersion: 8, NextSecurityEpoch: 9, NextSPI: 0x2002, OrdinarySuiteID: suite.SM4HCTR, NewOperationalRoot: append([]byte(nil), h.keys["next"].root...)}
	frame, err := h.service.ProtectRootPrepareFrame(context.Background(), "tenant-1", []byte{0x20, 1, 0, 0, 7}, cmd)
	if err != nil {
		h.t.Fatal(err)
	}
	return frame.Frame
}
func (h *tcFlightHarness) advance() {
	h.t.Helper()
	ctx := context.Background()
	if err := h.store.MarkTCRotationPrepared(ctx, "tenant-1", protocol.TCRotationState{Phase: protocol.TCRotationPrepared, TransactionID: 9, CurrentSPI: 0x2001, NextSPI: 0x2002, CurrentRootVersion: 7, NextRootVersion: 8}); err != nil {
		h.t.Fatal(err)
	}
	if err := h.service.AdvanceTCTransmitEpoch(ctx, "tenant-1"); err != nil {
		h.t.Fatal(err)
	}
}
func (h *tcFlightHarness) flight() *flightProcess {
	return startFlight(h.t, h.runner, h.vector, h.state, "OK")
}
func (h *tcFlightHarness) snapshot() [32]byte {
	h.t.Helper()
	raw, err := os.ReadFile(h.state)
	if err != nil {
		h.t.Fatal(err)
	}
	return sha256.Sum256(raw)
}
func (h *tcFlightHarness) unchanged(before [32]byte) {
	h.t.Helper()
	if h.snapshot() != before {
		h.t.Fatal("rejected/uncommitted frame changed the durable snapshot")
	}
}
func (h *tcFlightHarness) observe(r flightReply) {
	h.t.Helper()
	h.post("/api/v1/flight-status:observe", testDataToken(), map[string]any{"format_version": 1, "profile_digest": r.ProfileDigest, "self_test": "PASSED", "crypto_backend": "SOFTWARE", "current_spi": r.CurrentSPI, "next_spi": r.NextSPI, "recovery_spi": r.RecoverySPI, "security_epoch": r.Epoch, "root_version": r.RootVersion, "pending_root_present": r.Pending, "receive_count": r.ReceiveCount}, http.StatusNoContent)
	h.restartGround()
	saved, err := h.store.ReadFlightSecurityStatus(context.Background(), "tenant-1")
	if err != nil || saved.CurrentSPI != r.CurrentSPI || saved.SecurityEpoch != r.Epoch || saved.RootVersion != r.RootVersion || saved.PendingRootPresent != r.Pending {
		h.t.Fatalf("ground observation did not preserve flight state: %v", err)
	}
}
func wireIV(frame []byte) uint32 { return binary.BigEndian.Uint32(frame[7:11]) }
func rewriteFECF(frame []byte) {
	binary.BigEndian.PutUint16(frame[len(frame)-2:], tcCRC(frame[:len(frame)-2]))
}
func assertFlightState(t *testing.T, r flightReply, spi uint16, epoch, root uint32, pending bool) {
	t.Helper()
	if r.Diagnostic != "OK" || r.CurrentSPI != spi || r.NextSPI != spi+1 || r.Epoch != epoch || r.RootVersion != root || r.Pending != pending {
		t.Fatalf("unexpected flight state spi=%04x epoch=%d root=%d pending=%t diagnostic=%s", r.CurrentSPI, r.Epoch, r.RootVersion, r.Pending, r.Diagnostic)
	}
}
func assertCounter(t *testing.T, frame []byte, want uint32) {
	t.Helper()
	if wireIV(frame) != want {
		t.Fatalf("IV=%d want=%d", wireIV(frame), want)
	}
}
func (h *tcFlightHarness) corruptState() {
	h.t.Helper()
	raw, err := os.ReadFile(h.state)
	if err != nil {
		h.t.Fatal(err)
	}
	raw[0] ^= 1
	if err = os.WriteFile(h.state, raw, 0600); err != nil {
		h.t.Fatal(err)
	}
}
func (h *tcFlightHarness) failGroundFrame(body map[string]string) {
	h.post("/api/v1/tc:protect", testDataToken(), body, http.StatusBadRequest)
}

func (h *tcFlightHarness) converged(r flightReply) {
	h.t.Helper()
	current, err := h.store.GetTransmitAssociation(context.Background(), "tenant-1", protocol.DirectionTCTx)
	if err != nil || current.SPI != r.CurrentSPI || current.SecurityEpoch != r.Epoch || current.KeyVersion != r.RootVersion {
		h.t.Fatalf("ground and flight did not converge: %v", err)
	}
	h.observe(r)
}
