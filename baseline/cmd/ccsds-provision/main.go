// Command ccsds-provision performs offline initial provisioning for the
// mission-scoped CCSDS security associations. It exposes no network listener
// and never prints or persists plaintext key material.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
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
	defaultTenant      = "t-default"
	defaultPolicyID    = "default-v1"
	defaultPolicyVer   = 1
	defaultCurrentSPI  = 0x1001
	defaultRecoverySPI = 0x7001
	defaultAOSSPI      = 0x2001
	defaultEpoch       = 1
	defaultReplay      = 32
)

type profile struct {
	ordinarySuite string
	recoverySuite string
	aosSuite      string
}

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	tenantID := flag.String("tenant", defaultTenant, "tenant to provision")
	currentSPI := flag.Uint("tc-current-spi", defaultCurrentSPI, "ordinary TC Current SPI")
	recoverySPI := flag.Uint("tc-recovery-spi", defaultRecoverySPI, "Recovery GCM SPI")
	aosSPI := flag.Uint("aos-spi", defaultAOSSPI, "AOS receive SPI")
	epoch := flag.Uint("tc-security-epoch", defaultEpoch, "initial ordinary TC security epoch")
	replayWindow := flag.Uint("aos-replay-window", defaultReplay, "AOS replay window (1..64)")
	flag.Parse()

	if err := run(context.Background(), provisionOptions{
		configPath: *configPath, tenantID: *tenantID,
		currentSPI: *currentSPI, recoverySPI: *recoverySPI, aosSPI: *aosSPI,
		epoch: *epoch, replayWindow: *replayWindow,
	}); err != nil {
		slog.Error("CCSDS provisioning failed", "error", err)
		os.Exit(1)
	}
}

type provisionOptions struct {
	configPath   string
	tenantID     string
	currentSPI   uint
	recoverySPI  uint
	aosSPI       uint
	epoch        uint
	replayWindow uint
}

func run(ctx context.Context, options provisionOptions) error {
	if err := options.validate(); err != nil {
		return err
	}
	profile := tcProfile()
	cfg, err := config.Load(options.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer app.Store.Close()

	ids := provisionIDs(options.tenantID)
	keysToEnsure := []keySpec{
		{id: ids.operationalKey, name: "CCSDS TC operational root", suite: profile.ordinarySuite},
		{id: ids.recoveryKey, name: "CCSDS TC Recovery root", suite: profile.recoverySuite},
		{id: ids.aosKey, name: "CCSDS AOS receive key", suite: profile.aosSuite},
	}
	for _, spec := range keysToEnsure {
		if err := ensureProtocolKey(ctx, app, options.tenantID, spec); err != nil {
			return err
		}
	}

	associations := desiredAssociations(options, profile, ids)
	for _, association := range associations {
		created, err := ensureAssociation(ctx, app, association)
		if err != nil {
			return err
		}
		state := "verified"
		if created {
			state = "created"
		}
		slog.Info("CCSDS association ready", "association_id", association.ID,
			"direction", association.Direction, "state", association.State,
			"spi", fmt.Sprintf("0x%04X", association.SPI), "result", state)
	}
	slog.Info("CCSDS provisioning complete", "tenant_id", options.tenantID,
		"TC_profile", profile.ordinarySuite, "associations", len(associations))
	return nil
}

func (options provisionOptions) validate() error {
	if options.tenantID == "" {
		return errors.New("tenant is required")
	}
	if options.currentSPI > 0xffff || options.recoverySPI > 0xffff || options.aosSPI > 0xffff {
		return errors.New("SPI values must be in the range 0x0000..0xFFFF")
	}
	nextSPI := uint(ccsds.NextSPI(uint16(options.currentSPI)))
	if options.recoverySPI == options.currentSPI || options.recoverySPI == nextSPI ||
		options.aosSPI == options.currentSPI || options.aosSPI == nextSPI || options.aosSPI == options.recoverySPI {
		return errors.New("Current, Next, Recovery, and AOS SPIs must be distinct")
	}
	if options.epoch == 0 || options.epoch >= 0xffffffff {
		return errors.New("TC security epoch must be 1..4294967294")
	}
	if options.replayWindow == 0 || options.replayWindow > 64 {
		return errors.New("AOS replay window must be 1..64")
	}
	return nil
}

func tcProfile() profile {
	return profile{ordinarySuite: "SM4_HCTR", recoverySuite: "SM4_GCM", aosSuite: "SM4_GCM"}
}

type keySpec struct {
	id    string
	name  string
	suite string
}

func ensureProtocolKey(ctx context.Context, app *bootstrap.App, tenantID string, spec keySpec) error {
	existing, err := app.Store.GetKey(ctx, tenantID, spec.id)
	if err == nil {
		if existing.TenantID != tenantID || existing.Purpose != "encrypt_decrypt" ||
			existing.UsageScope != models.KeyUsageProtocol || existing.PolicyID != defaultPolicyID ||
			existing.SuiteID != spec.suite || existing.CurrentVersion != 1 || existing.Status != "ACTIVE" {
			return fmt.Errorf("existing protocol key %s does not match the strict provisioning profile", spec.id)
		}
		return nil
	}
	if !errors.Is(err, securitystate.ErrNotFound) {
		return fmt.Errorf("read protocol key %s: %w", spec.id, err)
	}
	suiteID, err := suite.Parse(spec.suite)
	if err != nil {
		return fmt.Errorf("parse protocol key suite %s: %w", spec.id, err)
	}
	versionID := spec.id + "-v1"
	material, err := app.Resolver.GenerateAndWrapDEK(ctx, suiteID, versionID)
	if err != nil {
		return fmt.Errorf("generate protocol key %s: %w", spec.id, err)
	}
	now := time.Now().UTC()
	key := &models.Key{ID: spec.id, TenantID: tenantID, Name: spec.name, Purpose: "encrypt_decrypt",
		UsageScope: models.KeyUsageProtocol, PolicyID: defaultPolicyID, SuiteID: spec.suite,
		CurrentVersion: 1, Status: "ACTIVE", Tags: map[string]string{"owner": "ccsds", "provisioning": "offline"},
		CreatedAt: now, UpdatedAt: now}
	version := &models.KeyVersion{ID: versionID, KeyID: spec.id, VersionNo: 1, SuiteID: spec.suite,
		WrappedDEK: material.WrappedDEK, WrapMetadata: material.WrapMetadata, Status: "ACTIVE", CreatedAt: now}
	if err := app.Store.CreateProtocolKey(ctx, key, version); err != nil {
		return fmt.Errorf("create protocol key %s: %w", spec.id, err)
	}
	return nil
}

type provisionedIDs struct {
	operationalKey string
	recoveryKey    string
	aosKey         string
	currentSA      string
	nextSA         string
	recoverySA     string
	aosSA          string
}

func provisionIDs(tenantID string) provisionedIDs {
	digest := sha256.Sum256([]byte(tenantID))
	scope := hex.EncodeToString(digest[:6])
	return provisionedIDs{
		operationalKey: "ccsds-" + scope + "-tc-operational-root",
		recoveryKey:    "ccsds-" + scope + "-tc-recovery-root",
		aosKey:         "ccsds-" + scope + "-aos-receive-key",
		currentSA:      "ccsds-" + scope + "-tc-current",
		nextSA:         "ccsds-" + scope + "-tc-next",
		recoverySA:     "ccsds-" + scope + "-tc-recovery",
		aosSA:          "ccsds-" + scope + "-aos-receive",
	}
}

func desiredAssociations(options provisionOptions, profile profile, ids provisionedIDs) []ccsds.SecurityAssociation {
	tcPrefix := noncePrefix(options.tenantID, "TC-ORDINARY")
	recoveryPrefix := noncePrefix(options.tenantID, "TC-RECOVERY")
	current := ccsds.SecurityAssociation{
		ID: ids.currentSA, TenantID: options.tenantID, SPI: uint16(options.currentSPI),
		Direction: ccsds.DirectionTCTx, KeyID: ids.operationalKey, KeyVersion: 1,
		SecurityEpoch: uint32(options.epoch), PolicyVersion: defaultPolicyVer,
		SuiteID: profile.ordinarySuite, State: ccsds.AssociationCurrent,
		Parameters: ccsds.ManagedParameters{TransmittedIVLength: ccsds.TCIVCounterLength, NoncePrefix: tcPrefix},
	}
	next := current
	next.ID = ids.nextSA
	next.SPI = ccsds.NextSPI(current.SPI)
	next.SecurityEpoch++
	next.State = ccsds.AssociationNext
	recovery := ccsds.SecurityAssociation{
		ID: ids.recoverySA, TenantID: options.tenantID, SPI: uint16(options.recoverySPI),
		Direction: ccsds.DirectionTCRecoveryTx, KeyID: ids.recoveryKey, KeyVersion: 1,
		PolicyVersion: defaultPolicyVer, SuiteID: profile.recoverySuite, State: ccsds.AssociationActive,
		Parameters: ccsds.ManagedParameters{TransmittedIVLength: ccsds.TCIVCounterLength,
			TagLength: ccsds.TCRecoveryTagLength, NoncePrefix: recoveryPrefix},
	}
	aos := ccsds.SecurityAssociation{
		ID: ids.aosSA, TenantID: options.tenantID, SPI: uint16(options.aosSPI),
		Direction: ccsds.DirectionAOSRx, KeyID: ids.aosKey, KeyVersion: 1,
		PolicyVersion: defaultPolicyVer, SuiteID: profile.aosSuite, State: ccsds.AssociationActive,
		Parameters: ccsds.ManagedParameters{SequenceNumberLength: 4, TransmittedIVLength: 12,
			TagLength: 16, ReplayWindow: uint8(options.replayWindow), NoncePrefix: []byte{}},
	}
	return []ccsds.SecurityAssociation{current, next, recovery, aos}
}

func noncePrefix(tenantID, domain string) []byte {
	digest := sha256.Sum256([]byte("CCSDS-NONCE-PREFIX\x00" + tenantID + "\x00" + domain))
	return append([]byte(nil), digest[:ccsds.TCNoncePrefixLength]...)
}

func ensureAssociation(ctx context.Context, app *bootstrap.App, desired ccsds.SecurityAssociation) (bool, error) {
	if err := desired.Validate(); err != nil {
		return false, err
	}
	existing, err := app.CCSDSStore.GetAssociation(ctx, desired.TenantID, desired.ID)
	if err == nil {
		if !associationEqual(*existing, desired) {
			return false, fmt.Errorf("existing association %s does not match the strict provisioning profile", desired.ID)
		}
		return false, nil
	}
	if !errors.Is(err, ccsds.ErrAssociationNotFound) {
		return false, fmt.Errorf("read association %s: %w", desired.ID, err)
	}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{
		TenantID: desired.TenantID, ActorType: "system", ActorHash: "offline:ccsds-provision",
		Action: "ccsds.association.provision.requested", TargetType: "ccsds_association",
		TargetIDHash: shortHash(desired.ID), Result: "requested",
		Metadata: map[string]string{"direction": string(desired.Direction), "spi": fmt.Sprintf("0x%04X", desired.SPI)},
	}); err != nil {
		return false, fmt.Errorf("audit association provisioning: %w", err)
	}
	err = app.Store.CreateAssociation(ctx, desired)
	if err != nil {
		return false, fmt.Errorf("create association %s: %w", desired.ID, err)
	}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{
		TenantID: desired.TenantID, ActorType: "system", ActorHash: "offline:ccsds-provision",
		Action: "ccsds.association.provisioned", TargetType: "ccsds_association",
		TargetIDHash: shortHash(desired.ID), Result: "success",
		Metadata: map[string]string{"direction": string(desired.Direction), "spi": fmt.Sprintf("0x%04X", desired.SPI)},
	}); err != nil {
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
		left.Parameters.TagLength == right.Parameters.TagLength &&
		left.Parameters.ReplayWindow == right.Parameters.ReplayWindow &&
		bytes.Equal(left.Parameters.NoncePrefix, right.Parameters.NoncePrefix)
}

func shortHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}
