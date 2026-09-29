//go:build !downlink

package main

import (
	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/operations"
)

func wireDownlink(*bootstrap.App, *ccsdsapi.Handler, *operations.Deps) {}
