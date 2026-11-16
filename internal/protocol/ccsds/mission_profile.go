package ccsds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kvlt/key-vault/internal/crypto/suite"
	"gopkg.in/yaml.v3"
)

const MissionProfileVersion = 3

// MissionSecurityProfile contains the public parameters bound to both envelopes.
type MissionSecurityProfile struct {
	FormatVersion uint16           `yaml:"format_version" json:"format_version"`
	MissionID     string           `yaml:"mission_id" json:"mission_id"`
	TenantID      string           `yaml:"tenant_id" json:"tenant_id"`
	SpacecraftID  uint16           `yaml:"spacecraft_id" json:"spacecraft_id"`
	TC            MissionTCProfile `yaml:"tc" json:"tc"`
}

type MissionTCProfile struct {
	CurrentSPI             uint16 `yaml:"current_spi" json:"current_spi"`
	SecurityEpoch          uint32 `yaml:"security_epoch" json:"security_epoch"`
	CurrentRootVersion     uint32 `yaml:"current_root_version" json:"current_root_version"`
	NextRootVersion        uint32 `yaml:"next_root_version" json:"next_root_version"`
	NoncePrefixHex         string `yaml:"nonce_prefix_hex" json:"nonce_prefix_hex"`
	RecoverySPI            uint16 `yaml:"recovery_spi" json:"recovery_spi"`
	RecoveryRootVersion    uint32 `yaml:"recovery_root_version" json:"recovery_root_version"`
	RecoveryNoncePrefixHex string `yaml:"recovery_nonce_prefix_hex" json:"recovery_nonce_prefix_hex"`
}

// MissionAssociationIDs are stable persistence identifiers chosen by the
// offline provisioning adapter. Profile validation and association construction
// remain inside this module.
type MissionAssociationIDs struct {
	CurrentKey, NextKey, RecoveryKey string
	CurrentSA, NextSA, RecoverySA    string
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
		return nil, errors.New("ccsds: invalid mission profile document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("ccsds: mission profile contains multiple documents")
		}
		return nil, errors.New("ccsds: invalid mission profile trailer")
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
		tc.NextRootVersion <= tc.CurrentRootVersion || tc.RecoveryRootVersion == 0 {
		return errors.New("ccsds: invalid TC epoch or root version")
	}
	for name, value := range map[string]struct {
		value  string
		length int
	}{
		"ordinary nonce prefix": {tc.NoncePrefixHex, TCNoncePrefixLength},
		"recovery nonce prefix": {tc.RecoveryNoncePrefixHex, TCNoncePrefixLength},
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
	profile.TC.NoncePrefixHex = strings.ToLower(profile.TC.NoncePrefixHex)
	profile.TC.RecoveryNoncePrefixHex = strings.ToLower(profile.TC.RecoveryNoncePrefixHex)
	canonical, err := json.Marshal(profile)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
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
		SecurityEpoch: profile.TC.SecurityEpoch, PolicyVersion: policyVersion, SuiteID: suite.SM4GCM32.String(),
		State: AssociationCurrent, Parameters: ManagedParameters{TransmittedIVLength: TCOrdinaryControlLength, TagLength: TCOrdinaryTagLength, NoncePrefix: prefix}}
	next := SecurityAssociation{ID: ids.NextSA, TenantID: profile.TenantID, SPI: NextSPI(profile.TC.CurrentSPI),
		Direction: DirectionTCTx, KeyID: ids.NextKey, KeyVersion: profile.TC.NextRootVersion,
		SecurityEpoch: profile.TC.SecurityEpoch + 1, PolicyVersion: policyVersion, SuiteID: suite.SM4GCM32.String(),
		State: AssociationNext, Parameters: ManagedParameters{TransmittedIVLength: TCOrdinaryControlLength, TagLength: TCOrdinaryTagLength, NoncePrefix: append([]byte(nil), prefix...)}}
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

func decodeProfileHex(value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, fmt.Errorf("expected %d bytes of hexadecimal data", length)
	}
	return decoded, nil
}
