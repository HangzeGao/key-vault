// Package operations builds the single, non-secret read model used by local
// operators. It owns readiness semantics so HTTP and CLI adapters do not need
// to know how protocol, downlink, TPM, policy, and state-store details combine.
package operations

import (
	"context"
	"strconv"
	"time"

	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/downlink"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type StateStore interface {
	Ping(context.Context) error
	Diagnostics(context.Context) (*securitystate.Diagnostics, error)
}

type TCStatus interface {
	OperationsStatus(context.Context, string) (*protocol.OperationsStatus, error)
}

type DownlinkStatus interface {
	Status(context.Context) (downlink.Status, error)
}

type Resolver interface{ Ready() bool }
type Policies interface {
	Get(string) (*policy.Policy, error)
}

type Service struct {
	store     StateStore
	resolver  Resolver
	policies  Policies
	tc        TCStatus
	downlink  DownlinkStatus
	startTime time.Time
}

type Deps struct {
	Store    StateStore
	Resolver Resolver
	Policies Policies
	TC       TCStatus
	Downlink DownlinkStatus
}

func New(deps Deps) *Service {
	return &Service{store: deps.Store, resolver: deps.Resolver, policies: deps.Policies,
		tc: deps.TC, downlink: deps.Downlink, startTime: time.Now()}
}

type Check struct {
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

type Database struct {
	Connected      bool  `json:"connected"`
	IntegrityOK    bool  `json:"integrity_ok"`
	Schema         int   `json:"schema"`
	ExpectedSchema int   `json:"expected_schema"`
	DatabaseBytes  int64 `json:"database_bytes"`
	WALBytes       int64 `json:"wal_bytes"`
	Associations   int64 `json:"security_associations"`
	AuditEvents    int64 `json:"audit_events"`
}

type Association struct {
	ID                   string                    `json:"id"`
	SPI                  uint16                    `json:"spi"`
	Direction            protocol.Direction        `json:"direction"`
	State                protocol.AssociationState `json:"state"`
	SuiteID              string                    `json:"suite_id"`
	SecurityEpoch        uint32                    `json:"security_epoch"`
	KeyVersion           uint32                    `json:"key_version"`
	PolicyVersion        uint32                    `json:"policy_version"`
	SequenceNumberLength int                       `json:"sequence_number_length"`
	TransmittedIVLength  int                       `json:"transmitted_iv_length"`
	TagLength            int                       `json:"tag_length"`
	ReplayWindow         uint8                     `json:"replay_window"`
	NextIVCounter        *uint64                   `json:"next_iv_counter,omitempty"`
	ReplayHighest        *uint64                   `json:"replay_highest,omitempty"`
	ReplaySeen           bool                      `json:"replay_seen"`
}

type TCRotation struct {
	Phase              protocol.TCRotationPhase `json:"phase"`
	TransactionID      string                   `json:"transaction_id"`
	CurrentSPI         uint16                   `json:"current_spi"`
	NextSPI            uint16                   `json:"next_spi"`
	CurrentRootVersion uint32                   `json:"current_root_version"`
	NextRootVersion    uint32                   `json:"next_root_version"`
	Evidence           string                   `json:"evidence"`
}

type Flight struct {
	ObservedAt              time.Time                    `json:"observed_at"`
	SelfTest                protocol.FlightSelfTestState `json:"self_test"`
	CryptoBackend           protocol.FlightCryptoBackend `json:"crypto_backend"`
	CurrentSPI              uint16                       `json:"current_spi"`
	NextSPI                 uint16                       `json:"next_spi"`
	RecoverySPI             uint16                       `json:"recovery_spi"`
	SecurityEpoch           uint32                       `json:"security_epoch"`
	RootVersion             uint32                       `json:"root_version"`
	PendingRootPresent      bool                         `json:"pending_root_present"`
	ReceiveCount            uint64                       `json:"receive_count"`
	LastReceiveUS           uint64                       `json:"last_receive_us"`
	MaxReceiveUS            uint64                       `json:"max_receive_us"`
	CycleLimitExceededCount uint64                       `json:"cycle_limit_exceeded_count"`
	ClockAnomalyCount       uint64                       `json:"clock_anomaly_count"`
}

type Snapshot struct {
	ObservedAt    time.Time        `json:"observed_at"`
	Status        string           `json:"status"`
	Ready         bool             `json:"ready"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Checks        map[string]Check `json:"checks"`
	Database      Database         `json:"database"`
	TC            struct {
		Current  *Association `json:"current"`
		Next     *Association `json:"next"`
		Recovery *Association `json:"recovery"`
	} `json:"tc"`
	TCRotation           *TCRotation     `json:"tc_rotation,omitempty"`
	DownlinkFormat       string          `json:"downlink_format"`
	Downlink             downlink.Status `json:"downlink"`
	ProfileDigest        string          `json:"profile_digest"`
	Flight               *Flight         `json:"flight,omitempty"`
	FlightReconciliation string          `json:"flight_reconciliation"`
	Warnings             []string        `json:"warnings"`
}

func (s *Service) Snapshot(ctx context.Context, tenantID string) (*Snapshot, error) {
	result := &Snapshot{ObservedAt: time.Now().UTC(), Status: "READY", Ready: true,
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()), Checks: make(map[string]Check),
		Warnings: make([]string, 0), Database: Database{ExpectedSchema: 3}}
	degrade := func(name, summary string) {
		result.Checks[name] = Check{Status: "degraded", Summary: summary}
		result.Ready = false
		if result.Status == "READY" {
			result.Status = "DEGRADED"
		}
	}
	ok := func(name, summary string) { result.Checks[name] = Check{Status: "ok", Summary: summary} }

	if s.store == nil || s.store.Ping(ctx) != nil {
		degrade("state", "SQLite security state unavailable")
	} else {
		ok("state", "SQLite security state available")
		diagnostics, err := s.store.Diagnostics(ctx)
		if err != nil {
			degrade("database", "security state diagnostics unavailable")
		} else {
			result.Database = Database{Connected: true, IntegrityOK: diagnostics.IntegrityOK,
				Schema: diagnostics.Schema, ExpectedSchema: 3, DatabaseBytes: diagnostics.DatabaseSize,
				WALBytes: diagnostics.WALSize, Associations: diagnostics.Associations, AuditEvents: diagnostics.AuditEvents}
			if !diagnostics.IntegrityOK || diagnostics.Schema != 3 {
				degrade("database", "security state integrity or schema check failed")
			} else {
				ok("database", "security state integrity and schema verified")
			}
		}
	}
	if s.resolver == nil || !s.resolver.Ready() {
		degrade("tpm_storage", "TPM sealed-object storage unavailable")
	} else {
		ok("tpm_storage", "TPM sealed-object storage available")
	}
	if s.policies == nil {
		degrade("policy", "CCSDS policy unavailable")
	} else if _, err := s.policies.Get("default-v1"); err != nil {
		degrade("policy", "CCSDS policy unavailable")
	} else {
		ok("policy", "CCSDS policy loaded")
	}

	if s.tc == nil {
		degrade("tc", "TC security service unavailable")
	} else {
		status, err := s.tc.OperationsStatus(ctx, tenantID)
		if err != nil {
			degrade("tc", "TC operations state unavailable")
		} else {
			result.TC.Current, result.TC.Next, result.TC.Recovery = mapAssociation(status.TCCurrent), mapAssociation(status.TCNext), mapAssociation(status.TCRecovery)
			result.DownlinkFormat, result.ProfileDigest = status.DownlinkFormat, status.ProfileDigest
			result.FlightReconciliation = status.FlightReconciliation
			result.Warnings = append(result.Warnings, status.Warnings...)
			if status.Ready {
				ok("tc", "TC associations and flight state ready")
			} else {
				degrade("tc", "TC operations state is not ready")
			}
			if status.TCRotation != nil {
				evidence := "RECOVERY_FRAME_PRODUCED"
				if status.TCRotation.Phase == protocol.TCRotationSwitching {
					evidence = "GROUND_PROMOTED"
				}
				if status.TCRotation.Phase == protocol.TCRotationActive {
					evidence = "FIRST_NEXT_FRAME_PRODUCED"
				}
				result.TCRotation = &TCRotation{Phase: status.TCRotation.Phase, TransactionID: strconv.FormatUint(status.TCRotation.TransactionID, 10),
					CurrentSPI: status.TCRotation.CurrentSPI, NextSPI: status.TCRotation.NextSPI,
					CurrentRootVersion: status.TCRotation.CurrentRootVersion, NextRootVersion: status.TCRotation.NextRootVersion, Evidence: evidence}
			}
			if f := status.FlightStatus; f != nil {
				result.Flight = &Flight{ObservedAt: f.ObservedAt, SelfTest: f.SelfTest, CryptoBackend: f.CryptoBackend,
					CurrentSPI: f.CurrentSPI, NextSPI: f.NextSPI, RecoverySPI: f.RecoverySPI, SecurityEpoch: f.SecurityEpoch,
					RootVersion: f.RootVersion, PendingRootPresent: f.PendingRootPresent, ReceiveCount: f.ReceiveCount,
					LastReceiveUS: f.LastReceiveUS, MaxReceiveUS: f.MaxReceiveUS, CycleLimitExceededCount: f.CycleLimitExceededCount, ClockAnomalyCount: f.ClockAnomalyCount}
			}
		}
	}
	if s.downlink == nil {
		degrade("downlink", "raw downlink service unavailable")
	} else if value, err := s.downlink.Status(ctx); err != nil {
		degrade("downlink", "raw downlink state unavailable")
	} else {
		result.Downlink = value
		switch {
		case !value.Provisioned:
			result.Status = "UNCONFIGURED"
			result.Ready = false
			degrade("downlink", "raw downlink KEK set is not provisioned")
		case value.CurrentGeneration == 0:
			degrade("downlink", "raw downlink has no Current DEK batch")
		case !value.CurrentObserved:
			degrade("downlink", "Current DEK batch is not observed; next generation is blocked")
		default:
			ok("downlink", "raw downlink key state ready")
		}
	}
	return result, nil
}

func mapAssociation(state *protocol.AssociationRuntimeState) *Association {
	if state == nil {
		return nil
	}
	return &Association{ID: state.ID, SPI: state.SPI, Direction: state.Direction, State: state.State, SuiteID: state.SuiteID,
		SecurityEpoch: state.SecurityEpoch, KeyVersion: state.KeyVersion, PolicyVersion: state.PolicyVersion,
		SequenceNumberLength: state.SequenceNumberLength, TransmittedIVLength: state.TransmittedIVLength,
		TagLength: state.TagLength, ReplayWindow: state.ReplayWindow, NextIVCounter: state.NextIVCounter,
		ReplayHighest: state.ReplayHighest, ReplaySeen: state.ReplaySeen}
}
