package ccsds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validMissionProfile = `format_version: 3
mission_id: demo-sat
tenant_id: tenant-1
spacecraft_id: 291
tc:
  current_spi: 4097
  security_epoch: 9
  current_root_version: 7
  next_root_version: 8
  nonce_prefix_hex: "102030405060"
  recovery_spi: 28673
  recovery_root_version: 3
  recovery_nonce_prefix_hex: "a0a1a2a3a4a5"
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

func TestMissionProfileOwnsGroundAndRecoveryConfiguration(t *testing.T) {
	profile := loadMissionProfile(t)
	digest, err := profile.Digest()
	if err != nil || digest == [32]byte{} {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
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

}

func TestMissionProfileParsingAndValidationFailClosed(t *testing.T) {
	if _, err := DecodeMissionSecurityProfile(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	for name, input := range map[string]string{
		"plaintext root":               strings.Replace(validMissionProfile, "  current_spi:", "  current_operational_root_hex: secret\n  current_spi:", 1),
		"unknown":                      strings.Replace(validMissionProfile, "mission_id: demo-sat", "unknown: x\nmission_id: demo-sat", 1),
		"duplicate":                    strings.Replace(validMissionProfile, "mission_id: demo-sat", "mission_id: one\nmission_id: two", 1),
		"multiple":                     validMissionProfile + "---\nformat_version: 3\n",
		"trailer syntax":               validMissionProfile + "broken: [unterminated\n",
		"bad hex":                      strings.Replace(validMissionProfile, "102030405060", "00", 1),
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
		func(p *MissionSecurityProfile) { p.FormatVersion = 1 },
		func(p *MissionSecurityProfile) { p.MissionID = "" },
		func(p *MissionSecurityProfile) { p.SpacecraftID = 0x400 },
		func(p *MissionSecurityProfile) { p.TC.SecurityEpoch = 0 },
		func(p *MissionSecurityProfile) { p.TC.SecurityEpoch = ^uint32(0) },
		func(p *MissionSecurityProfile) { p.TC.NextRootVersion = p.TC.CurrentRootVersion },
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
	invalid := base
	invalid.TC.NoncePrefixHex = "00"
	if _, err := invalid.Associations(ids, 1); err == nil {
		t.Fatal("invalid profile associations accepted")
	}
	if _, err := invalid.Digest(); err == nil {
		t.Fatal("invalid profile digest accepted")
	}
	uppercase := base
	uppercase.TC.RecoveryNoncePrefixHex = strings.ToUpper(base.TC.RecoveryNoncePrefixHex)
	if got, _ := uppercase.Digest(); got == [32]byte{} {
		t.Fatal("valid uppercase hex rejected")
	} else if want, _ := base.Digest(); got != want {
		t.Fatal("hex case changed the public profile digest")
	}
}
