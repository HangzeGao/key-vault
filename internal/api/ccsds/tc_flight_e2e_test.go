package ccsds_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/kdf"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type e2eCore struct {
	root  []byte
	suite suite.ID
}

func (core e2eCore) ProtectDerived(_ context.Context, request protection.ProtectRequest,
	derivation protection.Derivation) (*protection.ProtectResult, error) {
	key, err := kdf.CMACCounter(core.root, core.suite, derivation.Label, derivation.Context)
	if err != nil {
		return nil, err
	}
	defer func() {
		for index := range key {
			key[index] = 0
		}
	}()
	primitive, err := aead.New(core.suite, key)
	if err != nil {
		return nil, err
	}
	data, tag := primitive.Encrypt(request.Data, request.Nonce, request.AAD)
	return &protection.ProtectResult{Data: data, Nonce: append([]byte(nil), request.Nonce...), Tag: tag,
		KeyVersion: request.KeyVersion, PolicyVersion: request.PolicyVersion, SuiteID: core.suite,
		ServiceType: core.suite.ServiceType()}, nil
}

func (e2eCore) Unprotect(context.Context, protection.UnprotectRequest) (*protection.UnprotectResult, error) {
	panic("not used")
}

func TestTCDataPlaneAPIProducesFlightAcceptedVector(t *testing.T) {
	values := readVector(t, "../../../testdata/ccsds_tc_sm4_hctr.txt")
	decode := func(name string) []byte {
		value, err := hex.DecodeString(values[name])
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	parse := func(name string, base, bits int) uint64 {
		value, err := strconv.ParseUint(values[name], base, bits)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	suiteID, err := suite.Parse(values["suite_id"])
	if err != nil {
		t.Fatal(err)
	}
	sa := protocol.SecurityAssociation{ID: "e2e-current", TenantID: "tenant-1", SPI: uint16(parse("spi", 16, 16)),
		Direction: protocol.DirectionTCTx, KeyID: "e2e-root", KeyVersion: uint32(parse("root_version", 10, 32)),
		SecurityEpoch: uint32(parse("security_epoch", 10, 32)), PolicyVersion: 1, SuiteID: suiteID.String(),
		State: protocol.AssociationCurrent, Parameters: protocol.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: decode("nonce_prefix")}}
	groundPath := filepath.Join(t.TempDir(), "ground.db")
	store, err := securitystate.Open(context.Background(), groundPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureTenant(context.Background(), "tenant-1", "E2E TEST ONLY"); err != nil {
		t.Fatal(err)
	}
	key := &models.Key{ID: sa.KeyID, TenantID: sa.TenantID, Name: "E2E TEST ONLY", Purpose: "encrypt_decrypt",
		UsageScope: models.KeyUsageProtocol, PolicyID: "default-v1", SuiteID: sa.SuiteID,
		CurrentVersion: sa.KeyVersion, Status: "ACTIVE"}
	version := &models.KeyVersion{ID: "e2e-version", KeyID: sa.KeyID, VersionNo: sa.KeyVersion,
		SuiteID: sa.SuiteID, SealedMaterial: []byte("TEST ONLY fixture"), Status: "ACTIVE"}
	if err := store.CreateProtocolKey(context.Background(), key, version); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAssociation(context.Background(), sa); err != nil {
		t.Fatal(err)
	}
	counter := uint32(parse("iv_counter", 16, 32))
	for index := uint32(0); index < counter; index++ {
		if _, err := store.NextTransmitCounter(context.Background(), sa.ID); err != nil {
			t.Fatal(err)
		}
	}
	security, err := protocol.New(e2eCore{root: decode("root"), suite: suiteID}, store, protocol.Options{
		MaxFrameLength: 2048, NodeID: "e2e-ground",
		TCSpacecraftID: uint16(parse("spacecraft_id", 16, 16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	clearFrame := buildClearTCFrame(decode("plaintext"))
	body, _ := json.Marshal(map[string]string{"frame": base64.StdEncoding.EncodeToString(clearFrame)})
	server := httptest.NewServer(authenticatedHandler(security))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/tc:protect", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s err=%v", response.StatusCode, responseBody, err)
	}
	var result struct {
		ProtectedFrame string `json:"protected_frame"`
	}
	if json.Unmarshal(responseBody, &result) != nil {
		t.Fatal("invalid response")
	}
	protected, err := base64.StdEncoding.DecodeString(result.ProtectedFrame)
	if err != nil || !bytes.Equal(protected, decode("protected_frame")) {
		t.Fatalf("API frame=%x want=%s err=%v", protected, values["protected_frame"], err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := securitystate.Open(context.Background(), groundPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if next, err := restored.NextTransmitCounter(context.Background(), sa.ID); err != nil || next != counter+1 {
		t.Fatalf("ground counter after restart=%d want=%d err=%v", next, counter+1, err)
	}
	if runner := os.Getenv("TC_E2E_FLIGHT_RUNNER"); runner != "" {
		testFlightProcessRecovery(t, runner, protected)
	}
}

func testFlightProcessRecovery(t *testing.T, runner string, frame []byte) {
	t.Helper()
	vector, err := filepath.Abs("../../../testdata/ccsds_tc_sm4_hctr.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct{ fault, first, restarted string }{
		{"none", "OK", "REPLAY_REJECTED"},
		{"before", "PERSISTENCE_FAILED", "OK"},
		{"after", "STORAGE_COMMIT_UNCERTAIN", "REPLAY_REJECTED"},
	} {
		t.Run("flight-process-"+scenario.fault, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "flight.test-state")
			if output, err := exec.Command(runner, vector, state, "commission").CombinedOutput(); err != nil {
				t.Fatalf("commission failed: %v %s", err, output)
			}
			invoke := func(fault, expected string) {
				t.Helper()
				output, err := exec.Command(runner, vector, state, "receive", hex.EncodeToString(frame), fault).CombinedOutput()
				if err != nil {
					t.Fatalf("flight process failed: %v %s", err, output)
				}
				var result struct {
					Status  string `json:"status"`
					Length  int    `json:"length"`
					Matches bool   `json:"matches"`
					Cleared bool   `json:"cleared"`
				}
				if err := json.Unmarshal(output, &result); err != nil || result.Status != expected {
					t.Fatalf("flight result=%s want=%s err=%v", output, expected, err)
				}
				if expected == "OK" {
					if !result.Matches || result.Length == 0 {
						t.Fatal("flight plaintext mismatch")
					}
				} else if !result.Cleared || result.Length != 0 {
					t.Fatal("flight released failed plaintext")
				}
			}
			invoke(scenario.fault, scenario.first)
			invoke("none", scenario.restarted)
			if err := os.Remove(state); err != nil {
				t.Fatal(err)
			}
			invoke("none", "STATE_INTEGRITY_FAILED")
		})
	}
}

func readVector(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("bad vector line %q", line)
		}
		values[parts[0]] = parts[1]
	}
	if scanner.Err() != nil {
		t.Fatal(scanner.Err())
	}
	return values
}

func buildClearTCFrame(data []byte) []byte {
	length := 5 + len(data) + 2
	header := []byte{0x20, 0x01, 0x04, 0, 0x07}
	encoded := length - 1
	header[2] = header[2]&0xfc | byte(encoded>>8)&0x03
	header[3] = byte(encoded)
	frame := append(header, data...)
	crc := tcCRC(frame)
	return append(frame, byte(crc>>8), byte(crc))
}

func tcCRC(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, value := range data {
		crc ^= uint16(value) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
