package ccsds_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/kdf"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
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
	store, err := protocol.NewMemoryStore(sa)
	if err != nil {
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
	request := httptest.NewRequest(http.MethodPost, "/ui/api/v1/ccsds/tc:protect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	authenticatedHandler(security, "ccsds:tc:protect").ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		ProtectedFrame string `json:"protected_frame"`
	}
	if json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatal("invalid response")
	}
	protected, err := base64.StdEncoding.DecodeString(result.ProtectedFrame)
	if err != nil || !bytes.Equal(protected, decode("protected_frame")) {
		t.Fatalf("API frame=%x want=%s err=%v", protected, values["protected_frame"], err)
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
