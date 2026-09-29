//go:build !downlink

package ccsds

import "net/http"

type downlinkHandler struct{}

func (*Handler) registerDownlink(*http.ServeMux) {}

func writeDownlinkError(http.ResponseWriter, error) bool { return false }
