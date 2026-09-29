//go:build downlink

package bootstrap

import (
	"context"
	"fmt"

	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

type downlinkState struct {
	Downlink       *downlink.Service
	DownlinkSealer *downlink.TPMSealer
}

func initDownlink(ctx context.Context, tpm provider.Provider, store *securitystate.Store, cfg *config.Config, baseline, policyDigest []byte) (downlinkState, error) {
	sealer, err := downlink.NewTPMSealer(ctx, tpm, storageName, cfg.Server.NodeID, baseline, policyDigest)
	if err != nil {
		return downlinkState{}, fmt.Errorf("bootstrap: downlink TPM sealer: %w", err)
	}
	service := downlink.NewService(store, sealer)
	if err := service.Load(ctx); err != nil {
		return downlinkState{}, fmt.Errorf("bootstrap: load downlink keys: %w", err)
	}
	return downlinkState{Downlink: service, DownlinkSealer: sealer}, nil
}

func (app *App) CloseDownlink() {
	if app != nil && app.Downlink != nil {
		app.Downlink.Close()
	}
}
