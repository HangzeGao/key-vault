//go:build downlink

package main

import (
	"context"

	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/operations"
)

type downlinkStatusAdapter struct{ service *downlink.Service }

func (adapter downlinkStatusAdapter) DownlinkStatus(ctx context.Context) (operations.DownlinkState, error) {
	status, err := adapter.service.Status(ctx)
	if err != nil {
		return operations.DownlinkState{}, err
	}
	return operations.DownlinkState{Provisioned: status.Provisioned, ActiveKEKSlot: status.ActiveKEKSlot,
		CurrentGeneration: status.CurrentGeneration, CurrentObserved: status.CurrentObserved,
		PreviousGeneration: status.PreviousGeneration}, nil
}

func wireDownlink(app *bootstrap.App, handler *ccsdsapi.Handler, deps *operations.Deps) {
	handler.SetDownlink(app.Downlink)
	deps.Downlink = downlinkStatusAdapter{service: app.Downlink}
}
