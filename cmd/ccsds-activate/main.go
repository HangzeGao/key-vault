// Command ccsds-activate is the controlled ground-local adapter that promotes
// one already PREPARED TC rotation. It emits no on-wire management command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/kvlt/key-vault/internal/audit/redaction"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func main() {
	configPath := flag.String("config", "", "path to ground YAML configuration")
	tenantID := flag.String("tenant", "", "tenant with one PREPARED TC rotation")
	reason := flag.String("reason", "", "operator change reason")
	ticketID := flag.String("ticket-id", "", "approved change ticket")
	flag.Parse()
	if err := run(context.Background(), options{configPath: *configPath, tenantID: *tenantID,
		reason: *reason, ticketID: *ticketID}); err != nil {
		slog.Error("TC rotation activation failed", "error", err)
		os.Exit(1)
	}
}

type options struct{ configPath, tenantID, reason, ticketID string }

func (value options) validate() error {
	if value.tenantID == "" || value.reason == "" || value.ticketID == "" {
		return errors.New("tenant, reason, and ticket-id are required")
	}
	return nil
}

func run(ctx context.Context, value options) error {
	if err := value.validate(); err != nil {
		return err
	}
	cfg, err := config.Load(value.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer app.Store.Close()
	status, err := app.CCSDSFrameSecurity.OperationsStatus(ctx, value.tenantID)
	if err != nil {
		return err
	}
	if status.TCRotation == nil || status.TCRotation.Phase != ccsds.TCRotationPrepared {
		return errors.New("TC rotation is not PREPARED")
	}
	rotation := *status.TCRotation
	targetIDHash := redaction.ShortHash(fmt.Sprintf("%d", rotation.TransactionID))
	metadata := map[string]string{"reason": value.reason, "ticket_id": value.ticketID,
		"current_spi": fmt.Sprintf("0x%04X", rotation.CurrentSPI), "next_spi": fmt.Sprintf("0x%04X", rotation.NextSPI),
		"current_root_version": fmt.Sprint(rotation.CurrentRootVersion), "next_root_version": fmt.Sprint(rotation.NextRootVersion)}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{TenantID: value.tenantID,
		ActorType: "operator", ActorHash: "offline:ccsds-activate", Action: "ccsds.tc_rotation.activate.requested",
		TargetType: "ccsds_rotation", TargetIDHash: targetIDHash, Result: "requested",
		Metadata: metadata}); err != nil {
		return fmt.Errorf("audit activation request: %w", err)
	}
	if err := app.CCSDSFrameSecurity.AdvanceTCTransmitEpoch(ctx, value.tenantID); err != nil {
		metadata["error_code"] = "CCSDS_STATE_REJECTED"
		_ = app.AuditChain.Record(ctx, auditchain.RecordRequest{TenantID: value.tenantID,
			ActorType: "operator", ActorHash: "offline:ccsds-activate", Action: "ccsds.tc_rotation.activate.failed",
			TargetType: "ccsds_rotation", TargetIDHash: targetIDHash, Result: "failed",
			Metadata: metadata})
		return err
	}
	if err := app.AuditChain.Record(ctx, auditchain.RecordRequest{TenantID: value.tenantID,
		ActorType: "operator", ActorHash: "offline:ccsds-activate", Action: "ccsds.tc_rotation.activate.succeeded",
		TargetType: "ccsds_rotation", TargetIDHash: targetIDHash, Result: "success",
		Metadata: metadata}); err != nil {
		return fmt.Errorf("rotation advanced but success audit failed: %w", err)
	}
	slog.Info("TC rotation is SWITCHING; the next protected TC frame uses the staged SPI",
		"tenant_id", value.tenantID, "next_spi", fmt.Sprintf("0x%04X", rotation.NextSPI))
	return nil
}
