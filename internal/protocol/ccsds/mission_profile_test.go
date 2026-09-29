package ccsds

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validMissionProfile = `format_version: 1
mission_id: demo-sat
tenant_id: tenant-1
spacecraft_id: 291
tc:
  current_spi: 4097
  security_epoch: 9
  current_root_version: 7
  current_operational_root_hex: "00112233445566778899aabbccddeeff"
  next_root_version: 8
  next_operational_root_hex: "102132435465768798a9bacbdcedfe0f"
  nonce_prefix_hex: "102030405060"
  recovery_spi: 28673
  recovery_root_version: 3
  recovery_root_hex: "0123456789abcdeffedcba9876543210"
  recovery_nonce_prefix_hex: "a0a1a2a3a4a5"
  recovery_transaction_id: 72623859790382856
  recovery_primary_header_hex: "2001000001"
`

func loadMissionProfile(t *testing.T) *MissionSecurityProfile {
	t.Helper()
	profile, err := DecodeMissionSecurityProfile(strings.NewReader(validMissionProfile))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestExampleMissionProfile(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "..", "examples", "mission-security-profile.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := DecodeMissionSecurityProfile(file); err != nil {
		t.Fatal(err)
	}
}

func TestMissionProfileOwnsGroundFlightAndRecoveryConfiguration(t *testing.T) {
	profile := loadMissionProfile(t)
	digest, err := profile.Digest()
	if err != nil || digest == [32]byte{} {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
	secrets, err := profile.Secrets()
	if err != nil || len(secrets.CurrentRoot) != 16 || len(secrets.NextRoot) != 16 ||
		bytes.Equal(secrets.CurrentRoot, secrets.NextRoot) {
		t.Fatalf("secrets=%+v err=%v", secrets, err)
	}
	defer secrets.Zeroize()
	ids := MissionAssociationIDs{CurrentKey: "kc", NextKey: "kn", RecoveryKey: "kr",
		CurrentSA: "sc", NextSA: "sn", RecoverySA: "sr"}
	associations, err := profile.Associations(ids, 1)
	if err != nil || len(associations) != 3 {
		t.Fatalf("associations=%+v err=%v", associations, err)
	}
	current, next := associations[0], associations[1]
	if current.KeyID == next.KeyID || current.KeyVersion != 7 || next.KeyVersion != 8 ||
		next.SPI != NextSPI(current.SPI) || next.SecurityEpoch != current.SecurityEpoch+1 {
		t.Fatalf("Current/Next not closed: current=%+v next=%+v", current, next)
	}
	command, header, err := profile.RootPrepareCommand()
	if err != nil || command.NewRootVersion != next.KeyVersion || command.NextSPI != next.SPI ||
		!bytes.Equal(command.NewOperationalRoot, secrets.NextRoot) || len(header) != TCPrimaryHeaderLength {
		t.Fatalf("command=%+v header=%x err=%v", command, header, err)
	}
	image, err := profile.MarshalInitialFlightNVM(profile.TC.CurrentRootVersion)
	if err != nil || len(image) != FlightNVMImageLength || string(image[:4]) != "TCS2" ||
		binary.BigEndian.Uint32(image[8:12]) != profile.TC.CurrentRootVersion ||
		!bytes.Equal(image[12:44], digest[:]) {
		t.Fatalf("NVM image len=%d err=%v", len(image), err)
	}
	checksum := binary.BigEndian.Uint32(image[len(image)-8 : len(image)-4])
	if checksum != crc32c(image[:len(image)-8]) || binary.BigEndian.Uint32(image[len(image)-4:]) != ^checksum {
		t.Fatal("NVM image integrity trailer mismatch")
	}
}

func TestMissionProfileParsingAndValidationFailClosed(t *testing.T) {
	if _, err := DecodeMissionSecurityProfile(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	for name, input := range map[string]string{
		"unknown":                      strings.Replace(validMissionProfile, "mission_id: demo-sat", "unknown: x\nmission_id: demo-sat", 1),
		"duplicate":                    strings.Replace(validMissionProfile, "mission_id: demo-sat", "mission_id: one\nmission_id: two", 1),
		"multiple":                     validMissionProfile + "---\nformat_version: 1\n",
		"trailer syntax":               validMissionProfile + "broken: [unterminated\n",
		"bad hex":                      strings.Replace(validMissionProfile, "00112233445566778899aabbccddeeff", "00", 1),
		"unsupported hardware profile": validMissionProfile + "downlink:\n  active_kek_slot: 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMissionSecurityProfile(strings.NewReader(input)); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	base := *loadMissionProfile(t)
	mutations := []func(*MissionSecurityProfile){
		func(p *MissionSecurityProfile) { p.FormatVersion = 2 },
		func(p *MissionSecurityProfile) { p.MissionID = "" },
		func(p *MissionSecurityProfile) { p.SpacecraftID = 0x400 },
		func(p *MissionSecurityProfile) { p.TC.SecurityEpoch = 0 },
		func(p *MissionSecurityProfile) { p.TC.SecurityEpoch = ^uint32(0) },
		func(p *MissionSecurityProfile) { p.TC.NextRootVersion = p.TC.CurrentRootVersion },
		func(p *MissionSecurityProfile) { p.TC.RecoveryTransactionID = 0 },
		func(p *MissionSecurityProfile) { p.TC.RecoverySPI = p.TC.CurrentSPI },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
	if _, err := base.Associations(MissionAssociationIDs{}, 1); err == nil {
		t.Fatal("empty IDs accepted")
	}
	ids := MissionAssociationIDs{CurrentKey: "kc", NextKey: "kn", RecoveryKey: "kr",
		CurrentSA: "sc", NextSA: "sn", RecoverySA: "sr"}
	if _, err := base.Associations(ids, 0); err == nil {
		t.Fatal("zero policy version accepted")
	}
	if _, err := base.MarshalInitialFlightNVM(0); err == nil {
		t.Fatal("zero NVM generation accepted")
	}
	var empty MissionSecrets
	empty.Zeroize()
	(*MissionSecrets)(nil).Zeroize()
	secrets, _ := base.Secrets()
	secrets.Zeroize()
	if !bytes.Equal(secrets.CurrentRoot, make([]byte, 16)) {
		t.Fatal("mission secrets were not zeroized")
	}
	invalid := base
	invalid.TC.CurrentRootHex = "00"
	if _, err := invalid.Associations(ids, 1); err == nil {
		t.Fatal("invalid profile associations accepted")
	}
	if _, err := invalid.Digest(); err == nil {
		t.Fatal("invalid profile digest accepted")
	}
	if _, err := invalid.Secrets(); err == nil {
		t.Fatal("invalid profile secrets accepted")
	}
	if _, _, err := invalid.RootPrepareCommand(); err == nil {
		t.Fatal("invalid recovery command accepted")
	}
	if _, err := invalid.MarshalInitialFlightNVM(1); err == nil {
		t.Fatal("invalid NVM profile accepted")
	}
}
