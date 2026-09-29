//go:build downlink

package main

import (
	"context"
	"fmt"

	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func provisionDownlink(ctx context.Context, app *bootstrap.App, profile *ccsds.MissionSecurityProfile, secrets *ccsds.MissionSecrets) error {
	if err := app.Downlink.Provision(ctx, secrets.KEKSet, profile.Downlink.ActiveKEKSlot); err != nil {
		return fmt.Errorf("provision downlink KEK set: %w", err)
	}
	return nil
}
