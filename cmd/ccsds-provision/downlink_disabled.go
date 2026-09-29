//go:build !downlink

package main

import (
	"context"

	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func provisionDownlink(context.Context, *bootstrap.App, *ccsds.MissionSecurityProfile, *ccsds.MissionSecrets) error {
	return nil
}
