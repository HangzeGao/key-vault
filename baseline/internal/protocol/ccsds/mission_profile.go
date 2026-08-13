package ccsds

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/kvlt/key-vault/internal/crypto/suite"
	"gopkg.in/yaml.v3"
)

const (
	MissionProfileVersion = 1
	FlightNVMImageVersion = 2
	FlightNVMImageLength  = 175
	flightNVMPayloadLen   = 123
)

var flightNVMMagic = [4]byte{'T', 'C', 'S', '2'}

// MissionSecurityProfile is the single controlled source used to provision
// both ground security state and the initial flight NVM image. Its root fields
// are secret and must only be handled by the offline provisioning process.
type MissionSecurityProfile struct {
	FormatVersion uint16                 `yaml:"format_version" json:"format_version"`
	MissionID     string                 `yaml:"mission_id" json:"mission_id"`
	TenantID      string                 `yaml:"tenant_id" json:"tenant_id"`
	SpacecraftID  uint16                 `yaml:"spacecraft_id" json:"spacecraft_id"`
	TC            MissionTCProfile       `yaml:"tc" json:"tc"`
	Downlink      MissionDownlinkProfile `yaml:"downlink" json:"downlink"`
}

type MissionTCProfile struct {
	CurrentSPI               uint16 `yaml:"current_spi" json:"current_spi"`
	SecurityEpoch            uint32 `yaml:"security_epoch" json:"security_epoch"`
	CurrentRootVersion       uint32 `yaml:"current_root_version" json:"current_root_version"`
	CurrentRootHex           string `yaml:"current_operational_root_hex" json:"current_operational_root_hex"`
	NextRootVersion          uint32 `yaml:"next_root_version" json:"next_root_version"`
	NextRootHex              string `yaml:"next_operational_root_hex" json:"next_operational_root_hex"`
	NoncePrefixHex           string `yaml:"nonce_prefix_hex" json:"nonce_prefix_hex"`
	RecoverySPI              uint16 `yaml:"recovery_spi" json:"recovery_spi"`
	RecoveryRootVersion      uint32 `yaml:"recovery_root_version" json:"recovery_root_version"`
	RecoveryRootHex          string `yaml:"recovery_root_hex" json:"recovery_root_hex"`
	RecoveryNoncePrefixHex   string `yaml:"recovery_nonce_prefix_hex" json:"recovery_nonce_prefix_hex"`
	RecoveryTransactionID    uint64 `yaml:"recovery_transaction_id" json:"recovery_transaction_id"`
	RecoveryPrimaryHeaderHex string `yaml:"recovery_primary_header_hex" json:"recovery_primary_header_hex"`
}

type MissionDownlinkProfile struct {
	ActiveKEKSlot uint8  `yaml:"active_kek_slot" json:"active_kek_slot"`
	KEKSetHex     string `yaml:"kek_set_hex" json:"kek_set_hex"`
}

// MissionAssociationIDs are stable persistence identifiers chosen by the
// offline provisioning adapter. Profile validation and association construction
// remain inside this module.
type MissionAssociationIDs struct {
	CurrentKey, NextKey, RecoveryKey string
	CurrentSA, NextSA, RecoverySA    string
}

type MissionSecrets struct {
	CurrentRoot, NextRoot, RecoveryRoot, KEKSet []byte
}

// DecodeMissionSecurityProfile accepts one strict YAML document. Unknown and
// duplicate fields are rejected by yaml.v3 KnownFields and mapping validation.
func DecodeMissionSecurityProfile(reader io.Reader) (*MissionSecurityProfile, error) {
	if reader == nil {
		return nil, errors.New("ccsds: mission profile reader is required")
	}
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var profile MissionSecurityProfile
	if err := decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("ccsds: decode mission profile: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("ccsds: mission profile contains multiple documents")
		}
		return nil, fmt.Errorf("ccsds: decode mission profile trailer: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (profile MissionSecurityProfile) Validate() error {
	if profile.FormatVersion != MissionProfileVersion || profile.MissionID == "" || profile.TenantID == "" {
		return errors.New("ccsds: mission profile version, mission_id, and tenant_id are required")
	}
	if profile.SpacecraftID > 0x03ff {
		return errors.New("ccsds: spacecraft_id must fit the 10-bit TC field")
	}
	tc := profile.TC
	if tc.SecurityEpoch == 0 || tc.SecurityEpoch == ^uint32(0) || tc.CurrentRootVersion == 0 ||
		tc.NextRootVersion <= tc.CurrentRootVersion || tc.RecoveryRootVersion == 0 ||
		tc.RecoveryTransactionID == 0 {
		return errors.New("ccsds: invalid TC epoch, root version, or recovery transaction")
	}
	if profile.Downlink.ActiveKEKSlot > 7 {
		return errors.New("ccsds: active downlink KEK slot must be 0..7")
	}
	nextSPI := NextSPI(tc.CurrentSPI)
	if tc.RecoverySPI == tc.CurrentSPI || tc.RecoverySPI == nextSPI {
		return errors.New("ccsds: Current, Next, and Recovery SPIs must be distinct")
	}
	for name, value := range map[string]struct {
		value  string
		length int
	}{
		"current root": {tc.CurrentRootHex, 16}, "next root": {tc.NextRootHex, 16},
		"recovery root": {tc.RecoveryRootHex, 16}, "downlink KEK set": {profile.Downlink.KEKSetHex, 128},
		"ordinary nonce prefix":   {tc.NoncePrefixHex, TCNoncePrefixLength},
		"recovery nonce prefix":   {tc.RecoveryNoncePrefixHex, TCNoncePrefixLength},
		"recovery primary header": {tc.RecoveryPrimaryHeaderHex, TCPrimaryHeaderLength},
	} {
		if _, err := decodeProfileHex(value.value, value.length); err != nil {
			return fmt.Errorf("ccsds: invalid %s: %w", name, err)
		}
	}
	return nil
}

func (profile MissionSecurityProfile) Digest() ([32]byte, error) {
	if err := profile.Validate(); err != nil {
		return [32]byte{}, err
	}
	canonical, err := json.Marshal(profile)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func (profile MissionSecurityProfile) Secrets() (MissionSecrets, error) {
	if err := profile.Validate(); err != nil {
		return MissionSecrets{}, err
	}
	current, _ := decodeProfileHex(profile.TC.CurrentRootHex, 16)
	next, _ := decodeProfileHex(profile.TC.NextRootHex, 16)
	recovery, _ := decodeProfileHex(profile.TC.RecoveryRootHex, 16)
	kekSet, _ := decodeProfileHex(profile.Downlink.KEKSetHex, 128)
	return MissionSecrets{CurrentRoot: current, NextRoot: next, RecoveryRoot: recovery, KEKSet: kekSet}, nil
}

func (secrets *MissionSecrets) Zeroize() {
	if secrets == nil {
		return
	}
	for _, value := range [][]byte{secrets.CurrentRoot, secrets.NextRoot, secrets.RecoveryRoot, secrets.KEKSet} {
		for index := range value {
			value[index] = 0
		}
	}
}

func (profile MissionSecurityProfile) Associations(ids MissionAssociationIDs, policyVersion uint32) ([]SecurityAssociation, error) {
	if err := profile.Validate(); err != nil || policyVersion == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("ccsds: policy version is required")
	}
	for _, id := range []string{ids.CurrentKey, ids.NextKey, ids.RecoveryKey,
		ids.CurrentSA, ids.NextSA, ids.RecoverySA} {
		if id == "" {
			return nil, errors.New("ccsds: mission persistence identifiers are required")
		}
	}
	prefix, _ := decodeProfileHex(profile.TC.NoncePrefixHex, TCNoncePrefixLength)
	recoveryPrefix, _ := decodeProfileHex(profile.TC.RecoveryNoncePrefixHex, TCNoncePrefixLength)
	current := SecurityAssociation{ID: ids.CurrentSA, TenantID: profile.TenantID, SPI: profile.TC.CurrentSPI,
		Direction: DirectionTCTx, KeyID: ids.CurrentKey, KeyVersion: profile.TC.CurrentRootVersion,
		SecurityEpoch: profile.TC.SecurityEpoch, PolicyVersion: policyVersion, SuiteID: suite.SM4HCTR.String(),
		State: AssociationCurrent, Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, NoncePrefix: prefix}}
	next := SecurityAssociation{ID: ids.NextSA, TenantID: profile.TenantID, SPI: NextSPI(profile.TC.CurrentSPI),
		Direction: DirectionTCTx, KeyID: ids.NextKey, KeyVersion: profile.TC.NextRootVersion,
		SecurityEpoch: profile.TC.SecurityEpoch + 1, PolicyVersion: policyVersion, SuiteID: suite.SM4HCTR.String(),
		State: AssociationNext, Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, NoncePrefix: append([]byte(nil), prefix...)}}
	recovery := SecurityAssociation{ID: ids.RecoverySA, TenantID: profile.TenantID, SPI: profile.TC.RecoverySPI,
		Direction: DirectionTCRecoveryTx, KeyID: ids.RecoveryKey, KeyVersion: profile.TC.RecoveryRootVersion,
		PolicyVersion: policyVersion, SuiteID: suite.SM4GCM.String(), State: AssociationActive,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, TagLength: TCRecoveryTagLength, NoncePrefix: recoveryPrefix}}
	associations := []SecurityAssociation{current, next, recovery}
	for _, association := range associations {
		if err := association.Validate(); err != nil {
			return nil, err
		}
	}
	return associations, nil
}

func (profile MissionSecurityProfile) RootPrepareCommand() (RootPrepareCommand, []byte, error) {
	secrets, err := profile.Secrets()
	if err != nil {
		return RootPrepareCommand{}, nil, err
	}
	header, _ := decodeProfileHex(profile.TC.RecoveryPrimaryHeaderHex, TCPrimaryHeaderLength)
	return RootPrepareCommand{TransactionID: profile.TC.RecoveryTransactionID,
		ExpectedCurrentRootVersion: profile.TC.CurrentRootVersion, NewRootVersion: profile.TC.NextRootVersion,
		NextSecurityEpoch: profile.TC.SecurityEpoch + 1, NextSPI: NextSPI(profile.TC.CurrentSPI),
		OrdinarySuiteID: suite.SM4HCTR, NewOperationalRoot: secrets.NextRoot}, header, nil
}

// MarshalInitialFlightNVM emits the deterministic initial two-slot payload
// consumed by tcsec_nvm_decode. It includes Current and Recovery roots but not
// the staged Next root; Next enters flight only through authenticated Recovery.
func (profile MissionSecurityProfile) MarshalInitialFlightNVM(generation uint32) ([]byte, error) {
	if generation == 0 {
		return nil, errors.New("ccsds: NVM generation must be non-zero")
	}
	secrets, err := profile.Secrets()
	if err != nil {
		return nil, err
	}
	digest, _ := profile.Digest()
	prefix, _ := decodeProfileHex(profile.TC.NoncePrefixHex, TCNoncePrefixLength)
	recoveryPrefix, _ := decodeProfileHex(profile.TC.RecoveryNoncePrefixHex, TCNoncePrefixLength)
	image := make([]byte, FlightNVMImageLength)
	copy(image[:4], flightNVMMagic[:])
	binary.BigEndian.PutUint16(image[4:6], FlightNVMImageVersion)
	binary.BigEndian.PutUint16(image[6:8], flightNVMPayloadLen)
	binary.BigEndian.PutUint32(image[8:12], generation)
	copy(image[12:44], digest[:])
	offset := 44
	put16 := func(value uint16) { binary.BigEndian.PutUint16(image[offset:offset+2], value); offset += 2 }
	put32 := func(value uint32) { binary.BigEndian.PutUint32(image[offset:offset+4], value); offset += 4 }
	put64 := func(value uint64) { binary.BigEndian.PutUint64(image[offset:offset+8], value); offset += 8 }
	put := func(value []byte) { copy(image[offset:offset+len(value)], value); offset += len(value) }
	put16(profile.SpacecraftID)
	put16(uint16(suite.SM4HCTR))
	put(secrets.CurrentRoot)
	put32(profile.TC.CurrentRootVersion)
	put32(profile.TC.SecurityEpoch)
	put16(profile.TC.CurrentSPI)
	put(prefix)
	put32(0)
	put64(0)
	image[offset] = 0
	offset++ // ordinary replay
	image[offset] = 0
	offset++ // no pending root in initial image
	put16(0)
	put(make([]byte, 16))
	put32(0)
	put64(0)
	put16(uint16(suite.SM4GCM))
	put(secrets.RecoveryRoot)
	put32(profile.TC.RecoveryRootVersion)
	put16(profile.TC.RecoverySPI)
	put(recoveryPrefix)
	put32(0)
	put64(0)
	image[offset] = 0
	offset++
	if offset != FlightNVMImageLength-8 {
		return nil, errors.New("ccsds: internal NVM image length mismatch")
	}
	checksum := crc32c(image[:offset])
	binary.BigEndian.PutUint32(image[offset:offset+4], checksum)
	binary.BigEndian.PutUint32(image[offset+4:offset+8], ^checksum)
	return image, nil
}

func decodeProfileHex(value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("expected %d bytes of hexadecimal data", length)
	}
	return decoded, nil
}

func crc32c(data []byte) uint32 {
	crc := ^uint32(0)
	for _, value := range data {
		crc ^= uint32(value)
		for bit := 0; bit < 8; bit++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x82f63b78
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
