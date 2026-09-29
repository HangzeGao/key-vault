//go:build !downlink

package bootstrap

import (
	"context"

	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

type downlinkState struct{}

func initDownlink(context.Context, provider.Provider, *securitystate.Store, *config.Config, []byte, []byte) (downlinkState, error) {
	return downlinkState{}, nil
}

func (*App) CloseDownlink() {}
