// Command ccsds-provision consumes one controlled Mission Security Profile and
// creates matching ground state, flight NVM, Recovery frame, and hash evidence.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/securitystate"
)

const (
	defaultPolicyID  = "default-v1"
	defaultPolicyVer = 1
)

func main() {
	configPath := flag.String("config", "", "path to ground YAML configuration")
	profilePath := flag.String("mission-profile", "", "path to the controlled Mission Security Profile")
	artifactsDir := flag.String("artifacts-dir", "", "private directory for flight NVM, Recovery frame, and evidence")
	flag.Parse()
	if err := run(context.Background(), provisionOptions{configPath: *configPath,
		profilePath: *profilePath, artifactsDir: *artifactsDir}); err != nil {
		slog.Error("CCSDS provisioning failed", "error", err)
		os.Exit(1)
	}
}

type provisionOptions struct {
	configPath, profilePath, artifactsDir string
}

func (options provisionOptions) validate() error {
	if options.profilePath == "" || options.artifactsDir == "" {
		return errors.New("mission-profile and artifacts-dir are required")
	}
	return nil
}

func run(ctx context.Context, options provisionOptions) error {
	if err := options.validate(); err != nil {
		return err
	}
	file, err := os.Open(options.profilePath)
	if err != nil {
		return fmt.Errorf("open mission profile: %w", err)
	}
	profile, err := ccsds.DecodeMissionSecurityProfile(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("close mission profile: %w", closeErr)
	}
	digest, _ := profile.Digest()
	secrets, err := profile.Secrets()
	if err != nil {
		return err
	}
	defer secrets.Zeroize()

	cfg, err := config.Load(options.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.CCSDS.TCSpacecraftID != profile.SpacecraftID {
		return fmt.Errorf("mission profile spacecraft_id 0x%03X does not match ground config 0x%03X",
			profile.SpacecraftID, cfg.CCSDS.TCSpacecraftID)
	}
	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer app.TPM.Close()
	defer app.Store.Close()
	if err := app.Store.BindMissionProfile(ctx, profile.TenantID, digest); err != nil {
		return fmt.Errorf("bind mission profile digest: %w", err)
	}

	ids := provisionIDs(profile.TenantID, profile.TC.CurrentRootVersion, profile.TC.NextRootVersion)
	keySpecs := []keySpec{
		{id: ids.CurrentKey, name: "CCSDS TC current operational root", suite: "SM4_HCTR", version: profile.TC.CurrentRootVersion, material: secrets.CurrentRoot},
		{id: ids.NextKey, name: "CCSDS TC next operational root", suite: "SM4_HCTR", version: profile.TC.NextRootVersion, material: secrets.NextRoot},
		{id: ids.RecoveryKey, name: "CCSDS TC Recovery root", suite: "SM4_GCM", version: profile.TC.RecoveryRootVersion, material: secrets.RecoveryRoot},
	}
	for _, spec := range keySpecs {
		if err := ensureProtocolKey(ctx, app, profile.TenantID, hex.EncodeToString(digest[:]), spec); err != nil {
			return err
		}
	}
	associations, err := profile.Associations(ids, defaultPolicyVer)
	if err != nil {
		return err
	}
	for _, association := range associations {
		created, err := ensureAssociation(ctx, app, association)
		if err != nil {
			return err
		}
		result := "verified"
		if created {
			result = "created"
		}
		slog.Info("CCSDS association ready", "association_id", association.ID,
			"direction", association.Direction, "state", association.State,
			"spi", fmt.Sprintf("0x%04X", association.SPI), "result", result)
	}
	command, primaryHeader, err := profile.RootPrepareCommand()
	if err != nil {
		return err
	}
	defer clear(command.NewOperationalRoot)
	recoveryFrame, err := app.CCSDSFrameSecurity.ProtectRootPrepareFrame(ctx, profile.TenantID, primaryHeader, command)
	if err != nil {
		return fmt.Errorf("create authenticated Recovery frame: %w", err)
	}
	flightNVM, err := profile.MarshalInitialFlightNVM(profile.TC.CurrentRootVersion)
	if err != nil {
		return err
	}
	defer clear(flightNVM)
	if err := writeArtifacts(options.artifactsDir, *profile, digest, flightNVM, recoveryFrame.Frame); err != nil {
		return err
	}
	slog.Info("CCSDS mission provisioning complete", "mission_id", profile.MissionID,
		"tenant_id", profile.TenantID, "profile_sha256", hex.EncodeToString(digest[:]),
		"artifacts_dir", options.artifactsDir)
	return nil
}

type keySpec struct {
	id, name, suite string
	version         uint32
	material        []byte
}

func ensureProtocolKey(ctx context.Context, app *bootstrap.App, tenantID, profileDigest string, spec keySpec) error {
	existing, err := app.Store.GetKey(ctx, tenantID, spec.id)
	if err == nil {
		if existing.TenantID != tenantID || existing.Purpose != "encrypt_decrypt" ||
			existing.UsageScope != models.KeyUsageProtocol || existing.PolicyID != defaultPolicyID ||
			existing.SuiteID != spec.suite || existing.CurrentVersion != spec.version ||
			existing.Status != "ACTIVE" {
			return fmt.Errorf("existing protocol key %s does not match the strict mission profile", spec.id)
		}
		version, err := app.Store.GetKeyVersionByNo(ctx, spec.id, spec.version)
		if err != nil {
			return fmt.Errorf("read protocol key version %s: %w", spec.id, err)
		}
		plaintext, err := app.Resolver.UnsealKey(ctx, version.SealedMaterial, version.ID)
		if err != nil {
			return fmt.Errorf("verify protocol key %s: %w", spec.id, err)
		}
		defer clear(plaintext)
		if !bytes.Equal(plaintext, spec.material) {
			return fmt.Errorf("existing protocol key %s material does not match the mission profile", spec.id)
		}
		return nil
	}
	if !errors.Is(err, securitystate.ErrNotFound) {
		return fmt.Errorf("read protocol key %s: %w", spec.id, err)
	}
	suiteID, err := suite.Parse(spec.suite)
	if err != nil {
		return err
	}
	versionID := fmt.Sprintf("%s-v%d", spec.id, spec.version)
	material, err := app.Resolver.SealExternalKey(ctx, suiteID, versionID, spec.material)
	if err != nil {
		return fmt.Errorf("seal protocol key %s: %w", spec.id, err)
	}
	now := time.Now().UTC()
	key := &models.Key{ID: spec.id, TenantID: tenantID, Name: spec.name, Purpose: "encrypt_decrypt",
		UsageScope: models.KeyUsageProtocol, PolicyID: defaultPolicyID, SuiteID: spec.suite,
		CurrentVersion: spec.version, Status: "ACTIVE", Tags: map[string]string{"owner": "ccsds",
			"provisioning": "mission-profile", "mission_profile_sha256": profileDigest}, CreatedAt: now, UpdatedAt: now}
	version := &models.KeyVersion{ID: versionID, KeyID: spec.id, VersionNo: spec.version, SuiteID: spec.suite,
		SealedMaterial: material.SealedMaterial, Status: "ACTIVE", CreatedAt: now}
	if err := app.Store.CreateProtocolKey(ctx, key, version); err != nil {
		return fmt.Errorf("create protocol key %s: %w", spec.id, err)
	}
	return nil
}

type provisionedIDs = ccsds.MissionAssociationIDs

func provisionIDs(tenantID string, currentVersion, nextVersion uint32) provisionedIDs {
	digest := sha256.Sum256([]byte(tenantID))
	scope := hex.EncodeToString(digest[:6])
	prefix := "ccsds-" + scope
	return provisionedIDs{
		CurrentKey:  fmt.Sprintf("%s-tc-root-v%d", prefix, currentVersion),
		NextKey:     fmt.Sprintf("%s-tc-root-v%d", prefix, nextVersion),
		RecoveryKey: prefix + "-tc-recovery-root",
		CurrentSA:   fmt.Sprintf("%s-tc-sa-v%d", prefix, currentVersion),
		NextSA:      fmt.Sprintf("%s-tc-sa-v%d", prefix, nextVersion),
		RecoverySA:  prefix + "-tc-recovery",
	}
}

func ensureAssociation(ctx context.Context, app *bootstrap.App, desired ccsds.SecurityAssociation) (bool, error) {
	if err := desired.Validate(); err != nil {
		return false, err
	}
	existing, err := app.CCSDSStore.GetAssociation(ctx, desired.TenantID, desired.ID)
	if err == nil {
		if !associationEqual(*existing, desired) {
			return false, fmt.Errorf("existing association %s does not match the strict mission profile", desired.ID)
		}
		return false, nil
	}
	if !errors.Is(err, ccsds.ErrAssociationNotFound) {
		return false, fmt.Errorf("read association %s: %w", desired.ID, err)
	}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{TenantID: desired.TenantID,
		ActorType: "system", ActorHash: "offline:ccsds-provision", Action: "ccsds.association.provision.requested",
		TargetType: "ccsds_association", TargetIDHash: shortHash(desired.ID), Result: "requested",
		Metadata: map[string]string{"direction": string(desired.Direction), "spi": fmt.Sprintf("0x%04X", desired.SPI)}}); err != nil {
		return false, fmt.Errorf("audit association provisioning: %w", err)
	}
	if err := app.Store.CreateAssociation(ctx, desired); err != nil {
		return false, fmt.Errorf("create association %s: %w", desired.ID, err)
	}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{TenantID: desired.TenantID,
		ActorType: "system", ActorHash: "offline:ccsds-provision", Action: "ccsds.association.provisioned",
		TargetType: "ccsds_association", TargetIDHash: shortHash(desired.ID), Result: "success",
		Metadata: map[string]string{"direction": string(desired.Direction), "spi": fmt.Sprintf("0x%04X", desired.SPI)}}); err != nil {
		return true, fmt.Errorf("association %s was created but success audit failed: %w", desired.ID, err)
	}
	return true, nil
}

func associationEqual(left, right ccsds.SecurityAssociation) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.SPI == right.SPI &&
		left.Direction == right.Direction && left.KeyID == right.KeyID && left.KeyVersion == right.KeyVersion &&
		left.SecurityEpoch == right.SecurityEpoch && left.PolicyVersion == right.PolicyVersion &&
		left.SuiteID == right.SuiteID && left.State == right.State &&
		left.Parameters.SequenceNumberLength == right.Parameters.SequenceNumberLength &&
		left.Parameters.TransmittedIVLength == right.Parameters.TransmittedIVLength &&
		left.Parameters.TagLength == right.Parameters.TagLength && left.Parameters.ReplayWindow == right.Parameters.ReplayWindow &&
		bytes.Equal(left.Parameters.NoncePrefix, right.Parameters.NoncePrefix)
}

type releaseEvidence struct {
	FormatVersion       uint16 `json:"format_version"`
	MissionID           string `json:"mission_id"`
	TenantID            string `json:"tenant_id"`
	ProfileSHA256       string `json:"profile_sha256"`
	FlightNVMSHA256     string `json:"flight_nvm_sha256"`
	RecoveryFrameSHA256 string `json:"recovery_frame_sha256"`
	CurrentSPI          uint16 `json:"current_spi"`
	NextSPI             uint16 `json:"next_spi"`
	RecoverySPI         uint16 `json:"recovery_spi"`
	CurrentRootVersion  uint32 `json:"current_root_version"`
	NextRootVersion     uint32 `json:"next_root_version"`
}

func writeArtifacts(directory string, profile ccsds.MissionSecurityProfile, digest [32]byte,
	flightNVM, recoveryFrame []byte) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect artifact directory: %w", err)
	}
	evidence := releaseEvidence{FormatVersion: 1, MissionID: profile.MissionID, TenantID: profile.TenantID,
		ProfileSHA256: hex.EncodeToString(digest[:]), FlightNVMSHA256: digestBytes(flightNVM),
		RecoveryFrameSHA256: digestBytes(recoveryFrame), CurrentSPI: profile.TC.CurrentSPI,
		NextSPI: ccsds.NextSPI(profile.TC.CurrentSPI), RecoverySPI: profile.TC.RecoverySPI,
		CurrentRootVersion: profile.TC.CurrentRootVersion, NextRootVersion: profile.TC.NextRootVersion}
	encodedEvidence, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	encodedEvidence = append(encodedEvidence, '\n')
	for _, artifact := range []struct {
		name string
		data []byte
	}{
		{"flight-tcsec.nvm", flightNVM}, {"root-prepare.tc", recoveryFrame},
		// Evidence is installed last. Its hashes make any interrupted prior
		// artifact replacement detectable on the next verification.
		{"release-evidence.json", encodedEvidence},
	} {
		if err := writeAtomicPrivate(filepath.Join(directory, artifact.name), artifact.data); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomicPrivate(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tcsec-artifact-*")
	if err != nil {
		return fmt.Errorf("create temporary artifact: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install artifact %s: %w", filepath.Base(path), err)
	}
	return nil
}

func shortHash(value string) string { return digestBytes([]byte(value))[:16] }
func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
