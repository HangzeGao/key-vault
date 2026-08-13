package ccsds

import (
	"context"
	"errors"
	"time"
)

const FlightSecurityStatusVersion = 1

type FlightSelfTestState string
type FlightCryptoBackend string

const (
	FlightSelfTestPassed   FlightSelfTestState = "PASSED"
	FlightSelfTestLocked   FlightSelfTestState = "LOCKED"
	FlightBackendSoftware  FlightCryptoBackend = "SOFTWARE"
	FlightBackendARMv7NEON FlightCryptoBackend = "ARMV7_NEON"
)

// FlightSecurityStatus is the carrier-independent status semantic exported by
// the flight C module. An AOS housekeeping adapter may carry it without this
// package defining or depending on the AOS wire layout.
type FlightSecurityStatus struct {
	FormatVersion           uint16
	ProfileDigest           [32]byte
	SelfTest                FlightSelfTestState
	CryptoBackend           FlightCryptoBackend
	CurrentSPI              uint16
	NextSPI                 uint16
	RecoverySPI             uint16
	SecurityEpoch           uint32
	RootVersion             uint32
	PendingRootPresent      bool
	ReceiveCount            uint64
	LastReceiveUS           uint64
	MaxReceiveUS            uint64
	CycleLimitExceededCount uint64
	ClockAnomalyCount       uint64
}

type ObservedFlightSecurityStatus struct {
	FlightSecurityStatus
	ObservedAt time.Time
}

func (status FlightSecurityStatus) Validate() error {
	if status.FormatVersion != FlightSecurityStatusVersion || status.ProfileDigest == ([32]byte{}) ||
		(status.SelfTest != FlightSelfTestPassed && status.SelfTest != FlightSelfTestLocked) ||
		(status.CryptoBackend != FlightBackendSoftware && status.CryptoBackend != FlightBackendARMv7NEON) ||
		status.NextSPI != NextSPI(status.CurrentSPI) || status.SecurityEpoch == 0 || status.RootVersion == 0 {
		return errors.New("ccsds: invalid flight security status")
	}
	return nil
}

func (s *FrameSecurity) ObserveFlightSecurityStatus(ctx context.Context, tenantID string, status FlightSecurityStatus) error {
	if tenantID == "" {
		return errors.New("ccsds: tenant is required")
	}
	if err := status.Validate(); err != nil {
		return err
	}
	if _, err := s.store.ReadMissionProfileDigest(ctx, tenantID); err != nil {
		return err
	}
	return s.store.ObserveFlightSecurityStatus(ctx, tenantID, status)
}
