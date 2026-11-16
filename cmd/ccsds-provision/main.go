// Command ccsds-provision stages a device-bound ground root installation.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

type provisionOptions struct {
	configPath, profilePath, envelopePath, authorizationPath string
}

func main() {
	var options provisionOptions
	flag.StringVar(&options.configPath, "config", "", "path to trusted production configuration")
	flag.StringVar(&options.profilePath, "mission-profile", "", "path to the public mission manifest")
	flag.StringVar(&options.envelopePath, "envelope", "", "path to the device-bound ground envelope")
	flag.StringVar(&options.authorizationPath, "authorization", "", "path to the signed installation authorization")
	flag.Parse()
	if flag.NArg() != 0 {
		slog.Error("CCSDS staging takes no positional arguments")
		os.Exit(2)
	}
	if err := run(context.Background(), options); err != nil {
		slog.Error("CCSDS staging failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, options provisionOptions) error {
	if options.configPath == "" || options.profilePath == "" || options.envelopePath == "" || options.authorizationPath == "" {
		return errors.New("config, mission-profile, envelope and authorization are required")
	}
	cfg, err := config.LoadCommissioning(options.configPath)
	if err != nil || cfg.Environment != "production" || cfg.TPM.Provider != "native" || cfg.CCSDS.CommissioningTrustFile == "" {
		return errors.New("staging requires trusted production configuration and a native TPM")
	}
	profileData, err := input(options.profilePath)
	if err != nil {
		return errors.New("cannot read mission manifest")
	}
	defer clear(profileData)
	profile, err := ccsds.DecodeMissionSecurityProfile(bytes.NewReader(profileData))
	if err != nil || cfg.CCSDS.TCSpacecraftID != profile.SpacecraftID {
		return errors.New("invalid mission manifest or spacecraft mismatch")
	}
	digest, err := profile.Digest()
	if err != nil {
		return err
	}
	trust, err := config.OpenCommissioningTrust(cfg.CCSDS.CommissioningTrustFile)
	if err != nil {
		return errors.New("cannot open trusted commissioning enrollment")
	}
	defer trust.Close()
	request, err := loadInstallRequest(trust, options.envelopePath, options.authorizationPath, digest, time.Now())
	if err != nil {
		return err
	}
	if request.node != cfg.Server.NodeID || request.tenant != profile.TenantID {
		return errors.New("commissioning trust does not match the node and tenant")
	}
	ids := provisionIDs(profile.TenantID, profile.TC.CurrentRootVersion, profile.TC.NextRootVersion)
	associations, err := profile.Associations(ids, 1)
	if err != nil {
		return err
	}
	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initialize commissioning deployment: %w", err)
	}
	defer app.TPM.Close()
	defer app.Store.Close()
	tpm, ok := app.TPM.(*provider.NativeProvider)
	if !ok || app.AccessVerifier.TenantID() != profile.TenantID {
		return errors.New("deployment provider or tenant mismatch")
	}
	anchor, err := tpm.ReadCommissioningAnchor(ctx, request.anchor)
	if err != nil {
		return errors.New("registered installation anchor is unavailable")
	}
	commitment, err := app.Store.StageGroundCommissioning(ctx, profile.TenantID, request.binding.Transaction,
		request.authorized.RecordDigest(), anchor, func(existing []byte) ([]byte, error) {
			var sealed []byte
			err := tpm.WithImportKey(ctx, request.registration, func(key ecdh.KeyExchanger) error {
				return request.authorized.Import(key, request.issuer, func(roots []byte) error {
					var err error
					sealed, err = prepareInstallation(ctx, associations, roots, existing, app.Resolver)
					return err
				})
			})
			return sealed, err
		})
	if err != nil {
		return errors.New("cannot stage installation or existing installation conflicts")
	}
	if err := tpm.CommitCommissioningAnchor(ctx, request.anchor, commitment); err != nil {
		return errors.New("staged installation anchor not confirmed")
	}
	slog.Info("CCSDS installation staged", "transaction", hex.EncodeToString(request.binding.Transaction[:]),
		"profile_sha256", hex.EncodeToString(digest[:]), "stage_anchor_sha256", hex.EncodeToString(commitment[:]), "state", "INSTALLED_LOCKED")
	return nil
}

type installationKeys interface {
	SealExternalKey(context.Context, suite.ID, string, []byte) (*keyresolver.Material, error)
	UnsealKey(context.Context, []byte, string) ([]byte, error)
}

func prepareInstallation(ctx context.Context, associations []ccsds.SecurityAssociation, roots, existing []byte,
	keys installationKeys) ([]byte, error) {
	const rootSize = 16
	if len(associations) != 3 || len(roots) != 3*rootSize {
		return nil, errors.New("invalid installation contents")
	}
	var staged [3]ccsds.StagedAssociation
	if existing != nil && json.Unmarshal(existing, &staged) != nil {
		return nil, errors.New("invalid installation candidate")
	}
	// Associations are ordered Current, Next, Recovery. The envelope is
	// ordered Current, Recovery, Next.
	for pos, rootIndex := range [...]int{0, 2, 1} {
		association := associations[pos]
		suiteID, err := suite.Parse(association.SuiteID)
		if err != nil {
			return nil, err
		}
		versionID := fmt.Sprintf("%s-v%d", association.KeyID, association.KeyVersion)
		root := roots[rootIndex*rootSize : (rootIndex+1)*rootSize]
		sealed := staged[pos].SealedMaterial
		if existing == nil {
			material, err := keys.SealExternalKey(ctx, suiteID, versionID, root)
			if err != nil {
				return nil, err
			}
			sealed = material.SealedMaterial
		} else {
			plain, err := keys.UnsealKey(ctx, sealed, versionID)
			matches := err == nil && subtle.ConstantTimeCompare(plain, root) == 1
			clear(plain)
			if !matches {
				return nil, errors.New("candidate root does not match the authorized envelope")
			}
		}
		staged[pos] = ccsds.StagedAssociation{Association: association, VersionID: versionID, SealedMaterial: sealed}
	}
	return json.Marshal(staged)
}

func provisionIDs(tenantID string, currentVersion, nextVersion uint32) ccsds.MissionAssociationIDs {
	digest := sha256.Sum256([]byte(tenantID))
	prefix := "ccsds-" + hex.EncodeToString(digest[:6])
	return ccsds.MissionAssociationIDs{
		CurrentKey:  fmt.Sprintf("%s-tc-root-v%d", prefix, currentVersion),
		NextKey:     fmt.Sprintf("%s-tc-root-v%d", prefix, nextVersion),
		RecoveryKey: prefix + "-tc-recovery-root",
		CurrentSA:   fmt.Sprintf("%s-tc-sa-v%d", prefix, currentVersion),
		NextSA:      fmt.Sprintf("%s-tc-sa-v%d", prefix, nextVersion),
		RecoverySA:  prefix + "-tc-recovery",
	}
}
