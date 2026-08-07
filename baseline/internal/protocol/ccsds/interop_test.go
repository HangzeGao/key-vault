package ccsds

import (
	"bufio"
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

type tcVector struct {
	key, prefix, plaintext, protected []byte
	suiteID                           suite.ID
	spi                               uint16
	counter                           uint32
}

type vectorCore struct {
	key     []byte
	suiteID suite.ID
}

func (c vectorCore) Protect(_ context.Context, req protection.ProtectRequest) (*protection.ProtectResult, error) {
	primitive, err := aead.New(c.suiteID, c.key)
	if err != nil {
		return nil, err
	}
	data, tag := primitive.Encrypt(req.Data, req.Nonce, nil)
	return &protection.ProtectResult{
		Data: data, Nonce: append([]byte(nil), req.Nonce...), Tag: tag,
		KeyVersion: 1, PolicyVersion: 1, SuiteID: c.suiteID,
		ServiceType: suite.ServiceEncryptOnly,
	}, nil
}

func (vectorCore) Unprotect(context.Context, protection.UnprotectRequest) (*protection.UnprotectResult, error) {
	panic("not used")
}

func TestGroundTCFrameMatchesEmbeddedCVectors(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "aes-256-ctr", path: "../../../testdata/ccsds_tc_aes256_ctr.txt"},
		{name: "sm4-ctr", path: "../../../testdata/ccsds_tc_sm4_ctr.txt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vector := loadTCVector(t, test.path)
			sa := tcAssociation()
			sa.SPI = vector.spi
			sa.SuiteID = vector.suiteID.String()
			sa.Parameters.NoncePrefix = vector.prefix
			store, err := NewMemoryStore(sa)
			if err != nil {
				t.Fatal(err)
			}
			security, err := New(vectorCore{key: vector.key, suiteID: vector.suiteID}, store,
				Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "ground-test"})
			if err != nil {
				t.Fatal(err)
			}
			// Advance the deterministic in-memory allocator to the vector counter.
			for index := uint32(0); index < vector.counter; index++ {
				if _, err := store.NextTransmitCounter(context.Background(), sa.ID); err != nil {
					t.Fatal(err)
				}
			}
			header := []byte{0x20, 0x01, 0x04, 0, 0x07}
			setTCFrameLength(header, len(header)+len(vector.plaintext)+TCFECFLength)
			clearFrame := appendTCFECF(join(header, vector.plaintext))
			protected, err := security.ProtectTC(context.Background(), sa.TenantID, sa.ID, clearFrame)
			if err != nil {
				t.Fatal(err)
			}
			if !equalBytes(protected.Frame, vector.protected) {
				t.Fatalf("protected frame = %x, want %x", protected.Frame, vector.protected)
			}
		})
	}
}

func loadTCVector(t *testing.T, path string) tcVector {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid vector line %q", line)
		}
		values[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	decode := func(name string) []byte {
		value, err := hex.DecodeString(values[name])
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return value
	}
	spi, err := strconv.ParseUint(values["spi"], 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := strconv.ParseUint(values["iv_counter"], 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	suiteID, err := suite.Parse(values["suite_id"])
	if err != nil {
		t.Fatal(err)
	}
	return tcVector{
		key: decode("key"), prefix: decode("nonce_prefix"), plaintext: decode("plaintext"),
		protected: decode("protected_frame"), suiteID: suiteID, spi: uint16(spi), counter: uint32(counter),
	}
}
