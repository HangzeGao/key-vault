package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func TestProvisioningRequiresSingleMissionProfileContract(t *testing.T) {
	if err := (provisionOptions{}).validate(); err == nil {
		t.Fatal("empty options accepted")
	}
	if err := (provisionOptions{profilePath: "mission.yaml", artifactsDir: "out"}).validate(); err != nil {
		t.Fatal(err)
	}
	ids := provisionIDs("tenant-1", 7, 8)
	if ids.CurrentKey == ids.NextKey || ids.CurrentSA == "" || ids.RecoverySA == "" {
		t.Fatalf("IDs=%+v", ids)
	}
}

func TestProvisioningArtifactsArePairedAndHashed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	profile := ccsds.MissionSecurityProfile{MissionID: "mission", TenantID: "tenant-1",
		TC: ccsds.MissionTCProfile{CurrentSPI: 0x1001, RecoverySPI: 0x7001, CurrentRootVersion: 7, NextRootVersion: 8}}
	profileDigest := sha256.Sum256([]byte("profile"))
	recovery := []byte("complete-recovery-frame")
	if err := writeArtifacts(directory, profile, profileDigest, recovery); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name() != "release-evidence.json" || files[1].Name() != "root-prepare.tc" {
		t.Fatalf("unexpected artifacts: %v", files)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "release-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence releaseEvidence
	if json.Unmarshal(raw, &evidence) != nil || evidence.FormatVersion != 2 ||
		evidence.RecoveryFrameSHA256 != digestBytes(recovery) || evidence.NextSPI != 0x1002 {
		t.Fatalf("evidence=%+v", evidence)
	}
	if err := writeAtomicPrivate(filepath.Join(directory, "root-prepare.tc"), []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if value, _ := os.ReadFile(filepath.Join(directory, "root-prepare.tc")); string(value) != "replacement" {
		t.Fatalf("value=%q", value)
	}
}
