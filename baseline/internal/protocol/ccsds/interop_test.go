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
	"github.com/kvlt/key-vault/internal/crypto/kdf"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

type tcVector struct {
	root, prefix, plaintext, protected []byte
	suiteID                            suite.ID
	spi                                uint16
	counter                            uint32
	spacecraftID                       uint16
	rootVersion, securityEpoch         uint32
}

type vectorCore struct {
	root    []byte
	suiteID suite.ID
}

func (c vectorCore) ProtectDerived(ctx context.Context, req protection.ProtectRequest,
	derivation protection.Derivation) (*protection.ProtectResult, error) {
	workingKey, err := kdf.CMACCounter(c.root, c.suiteID, derivation.Label, derivation.Context)
	if err != nil {
		return nil, err
	}
	defer clearBytes(workingKey)
	return c.protect(ctx, req, workingKey)
}

func (c vectorCore) protect(_ context.Context, req protection.ProtectRequest, key []byte) (*protection.ProtectResult, error) {
	primitive, err := aead.New(c.suiteID, key)
	if err != nil {
		return nil, err
	}
	data, tag := primitive.Encrypt(req.Data, req.Nonce, req.AAD)
	return &protection.ProtectResult{
		Data: data, Nonce: append([]byte(nil), req.Nonce...), Tag: tag,
		KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion, SuiteID: c.suiteID,
		ServiceType: c.suiteID.ServiceType(),
	}, nil
}

func (vectorCore) Unprotect(context.Context, protection.UnprotectRequest) (*protection.UnprotectResult, error) {
	panic("not used")
}

func TestGroundOrdinaryTCMatchesFlightCVectors(t *testing.T) {
	for _, test := range []struct{ name, path string }{
		{name: "aes-256-ctr", path: "../../../testdata/ccsds_tc_aes256_ctr.txt"},
		{name: "sm4-ctr", path: "../../../testdata/ccsds_tc_sm4_ctr.txt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			vector := loadTCVector(t, test.path)
			sa := tcAssociation()
			sa.SPI, sa.SuiteID, sa.Parameters.NoncePrefix = vector.spi, vector.suiteID.String(), vector.prefix
			sa.KeyVersion, sa.SecurityEpoch = vector.rootVersion, vector.securityEpoch
			store, err := NewMemoryStore(sa)
			if err != nil {
				t.Fatal(err)
			}
			security, err := New(vectorCore{root: vector.root, suiteID: vector.suiteID}, store,
				Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "ground-test", TCSpacecraftID: vector.spacecraftID})
			if err != nil {
				t.Fatal(err)
			}
			advanceCounter(t, store, sa.ID, vector.counter)
			protected, err := security.ProtectTCData(context.Background(), sa.TenantID, vector.plaintext)
			if err != nil {
				t.Fatal(err)
			}
			frame := assembleVectorTCFrame([]byte{0x20, 0x01, 0x04, 0, 0x07}, protected.Data)
			if !equalBytes(frame, vector.protected) {
				t.Fatalf("protected frame = %x, want %x", frame, vector.protected)
			}
		})
	}
}

func TestGroundRootPrepareMatchesFlightCVectors(t *testing.T) {
	for _, test := range []struct{ name, path string }{
		{name: "aes-256-gcm", path: "../../../testdata/ccsds_tc_aes256_gcm_recovery.txt"},
		{name: "sm4-gcm", path: "../../../testdata/ccsds_tc_sm4_gcm_recovery.txt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			vector := loadTCVector(t, test.path)
			command, err := ParseRootPrepareCommand(vector.plaintext)
			if err != nil {
				t.Fatal(err)
			}
			sa := recoveryAssociation()
			sa.SPI, sa.SuiteID, sa.Parameters.NoncePrefix = vector.spi, vector.suiteID.String(), vector.prefix
			sa.KeyVersion = vector.rootVersion
			current := tcAssociation()
			current.SPI = command.NextSPI - 1
			current.SecurityEpoch = command.NextSecurityEpoch - 1
			current.KeyVersion = command.ExpectedCurrentRootVersion
			current.SuiteID = command.OrdinarySuiteID.String()
			next := current
			next.ID = "tx-next"
			next.SPI = command.NextSPI
			next.SecurityEpoch = command.NextSecurityEpoch
			next.KeyVersion = command.NewRootVersion
			next.State = AssociationNext
			store, err := NewMemoryStore(sa, current, next)
			if err != nil {
				t.Fatal(err)
			}
			security, err := New(vectorCore{root: vector.root, suiteID: vector.suiteID}, store,
				Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "ground-test", TCSpacecraftID: vector.spacecraftID})
			if err != nil {
				t.Fatal(err)
			}
			advanceCounter(t, store, sa.ID, vector.counter)
			protected, err := security.ProtectRootPrepareData(context.Background(), sa.TenantID, command)
			if err != nil {
				t.Fatal(err)
			}
			frame := assembleVectorTCFrame([]byte{0x20, 0x01, 0, 0, 0x01}, protected.Data)
			if !equalBytes(frame, vector.protected) {
				t.Fatalf("protected frame = %x, want %x", frame, vector.protected)
			}
		})
	}
}

func advanceCounter(t *testing.T, store Store, associationID string, counter uint32) {
	t.Helper()
	for index := uint32(0); index < counter; index++ {
		if _, err := store.NextTransmitCounter(context.Background(), associationID); err != nil {
			t.Fatal(err)
		}
	}
}

func assembleVectorTCFrame(primaryHeader, securityData []byte) []byte {
	header := append([]byte(nil), primaryHeader...)
	setTCFrameLength(header, len(header)+len(securityData)+TCFECFLength)
	return appendTCFECF(join(header, securityData))
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
		value, ok := values[name]
		if !ok {
			t.Fatalf("missing vector field %s", name)
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return decoded
	}
	parse := func(name string, base, bits int) uint64 {
		value, ok := values[name]
		if !ok {
			t.Fatalf("missing vector field %s", name)
		}
		parsed, err := strconv.ParseUint(value, base, bits)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return parsed
	}
	suiteID, err := suite.Parse(values["suite_id"])
	if err != nil {
		t.Fatal(err)
	}
	return tcVector{
		root: decode("root"), prefix: decode("nonce_prefix"), plaintext: decode("plaintext"),
		protected: decode("protected_frame"), suiteID: suiteID,
		spi: uint16(parse("spi", 16, 16)), counter: uint32(parse("iv_counter", 16, 32)),
		spacecraftID: uint16(parse("spacecraft_id", 16, 16)),
		rootVersion:  uint32(parse("root_version", 10, 32)), securityEpoch: uint32(parse("security_epoch", 10, 32)),
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
