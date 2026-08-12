package ccsds

import (
	"context"
	"encoding/hex"
	"sort"
)

const tcCounterCapacity = uint64(1) << 32

// AssociationRuntimeState is the non-secret operational projection of one
// security association. It deliberately excludes key IDs, nonce prefixes, and
// replay bitmaps so the operations plane cannot become a key-management plane.
type AssociationRuntimeState struct {
	ID                   string
	SPI                  uint16
	Direction            Direction
	State                AssociationState
	SuiteID              string
	SecurityEpoch        uint32
	KeyVersion           uint32
	PolicyVersion        uint32
	SequenceNumberLength int
	TransmittedIVLength  int
	TagLength            int
	ReplayWindow         uint8
	NextIVCounter        *uint64
	ReplayHighest        *uint64
	ReplaySeen           bool
}

type TCRotationPhase string

const (
	TCRotationPrepared  TCRotationPhase = "PREPARED"
	TCRotationSwitching TCRotationPhase = "SWITCHING"
	TCRotationActive    TCRotationPhase = "ACTIVE"
)

// TCRotationState is ground-local evidence. ACTIVE means the first protected
// Next-SPI frame was produced; it is not a claim that flight received it.
type TCRotationState struct {
	Phase              TCRotationPhase
	TransactionID      uint64
	CurrentSPI         uint16
	NextSPI            uint16
	CurrentRootVersion uint32
	NextRootVersion    uint32
}

// OperationsStatus is the single read model consumed by mission operations.
// State changes remain internal to the protocol module.
type OperationsStatus struct {
	Status               string
	Ready                bool
	TCCurrent            *AssociationRuntimeState
	TCNext               *AssociationRuntimeState
	TCRecovery           *AssociationRuntimeState
	TCRotation           *TCRotationState
	AOSActive            []AssociationRuntimeState
	AOSFormat            string
	ProfileDigest        string
	FlightStatus         *ObservedFlightSecurityStatus
	FlightReconciliation string
	Warnings             []string
}

// OperationsStatus returns a safe, tenant-scoped snapshot without allocating
// counters or mutating replay state.
func (s *FrameSecurity) OperationsStatus(ctx context.Context, tenantID string) (*OperationsStatus, error) {
	associations, err := s.store.ReadOperationsState(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	status := &OperationsStatus{Status: "UNCONFIGURED", AOSActive: make([]AssociationRuntimeState, 0),
		AOSFormat: "NOT_FROZEN", FlightReconciliation: "NOT_OBSERVED", Warnings: make([]string, 0)}
	digest, digestErr := s.store.ReadMissionProfileDigest(ctx, tenantID)
	if digestErr == nil {
		status.ProfileDigest = hex.EncodeToString(digest[:])
	} else if digestErr == ErrAssociationNotFound {
		status.Warnings = append(status.Warnings, "MISSION_PROFILE_NOT_BOUND")
	} else {
		return nil, digestErr
	}
	rotation, rotationErr := s.store.ReadTCRotationState(ctx, tenantID)
	if rotationErr == nil {
		status.TCRotation = rotation
	} else if rotationErr != ErrAssociationNotFound {
		return nil, rotationErr
	}
	for i := range associations {
		association := associations[i]
		switch {
		case association.Direction == DirectionTCTx && association.State == AssociationCurrent:
			if status.TCCurrent == nil {
				status.TCCurrent = cloneRuntimeState(association)
			} else {
				status.Warnings = append(status.Warnings, "TC_CURRENT_AMBIGUOUS")
			}
		case association.Direction == DirectionTCTx && association.State == AssociationNext:
			if status.TCNext == nil {
				status.TCNext = cloneRuntimeState(association)
			} else {
				status.Warnings = append(status.Warnings, "TC_NEXT_AMBIGUOUS")
			}
		case association.Direction == DirectionTCRecoveryTx && association.State == AssociationActive:
			if status.TCRecovery == nil {
				status.TCRecovery = cloneRuntimeState(association)
			} else {
				status.Warnings = append(status.Warnings, "TC_RECOVERY_AMBIGUOUS")
			}
		case association.Direction == DirectionAOSRx && association.State == AssociationActive:
			status.AOSActive = append(status.AOSActive, association)
		}
	}
	if status.TCCurrent == nil {
		status.Warnings = append(status.Warnings, "TC_CURRENT_MISSING")
	} else if status.TCCurrent.NextIVCounter != nil && *status.TCCurrent.NextIVCounter >= tcCounterCapacity*9/10 {
		status.Warnings = append(status.Warnings, "TC_IV_NEAR_EXHAUSTION")
	}
	if status.TCNext == nil {
		status.Warnings = append(status.Warnings, "TC_NEXT_MISSING")
	} else if status.TCCurrent != nil {
		if status.TCNext.KeyVersion <= status.TCCurrent.KeyVersion {
			status.Warnings = append(status.Warnings, "TC_NEXT_ROOT_NOT_ADVANCED")
		} else if status.TCRotation == nil {
			status.Warnings = append(status.Warnings, "TC_ROTATION_NOT_PREPARED")
		} else if status.TCRotation.CurrentSPI != status.TCCurrent.SPI || status.TCRotation.NextSPI != status.TCNext.SPI ||
			status.TCRotation.CurrentRootVersion != status.TCCurrent.KeyVersion ||
			status.TCRotation.NextRootVersion != status.TCNext.KeyVersion {
			status.Warnings = append(status.Warnings, "TC_ROTATION_STATE_MISMATCH")
		}
	}
	if status.TCRecovery == nil {
		status.Warnings = append(status.Warnings, "TC_RECOVERY_MISSING")
	}
	if len(status.AOSActive) == 0 {
		status.Warnings = append(status.Warnings, "AOS_ACTIVE_MISSING")
	}
	flight, flightErr := s.store.ReadFlightSecurityStatus(ctx, tenantID)
	if flightErr == nil {
		status.FlightStatus = flight
		status.FlightReconciliation = "MATCHED"
		if digestErr != nil || flight.ProfileDigest != digest {
			status.FlightReconciliation = "MISMATCH"
			status.Warnings = append(status.Warnings, "FLIGHT_PROFILE_MISMATCH")
		}
		if flight.SelfTest != FlightSelfTestPassed {
			status.FlightReconciliation = "MISMATCH"
			status.Warnings = append(status.Warnings, "FLIGHT_SELF_TEST_LOCKED")
		}
		if status.TCCurrent == nil || flight.CurrentSPI != status.TCCurrent.SPI ||
			flight.SecurityEpoch != status.TCCurrent.SecurityEpoch || flight.RootVersion != status.TCCurrent.KeyVersion ||
			status.TCRecovery == nil || flight.RecoverySPI != status.TCRecovery.SPI {
			status.FlightReconciliation = "MISMATCH"
			status.Warnings = append(status.Warnings, "FLIGHT_TC_STATE_MISMATCH")
		}
		if flight.CycleLimitExceededCount != 0 {
			status.Warnings = append(status.Warnings, "FLIGHT_CYCLE_LIMIT_EXCEEDED")
		}
		if flight.ClockAnomalyCount != 0 {
			status.Warnings = append(status.Warnings, "FLIGHT_CLOCK_ANOMALY")
		}
	} else if flightErr == ErrAssociationNotFound {
		status.Warnings = append(status.Warnings, "FLIGHT_STATUS_NOT_OBSERVED")
	} else {
		return nil, flightErr
	}
	sort.Slice(status.AOSActive, func(i, j int) bool { return status.AOSActive[i].SPI < status.AOSActive[j].SPI })
	status.Ready = status.TCCurrent != nil && status.TCNext != nil && status.TCRecovery != nil && len(status.AOSActive) > 0 && len(status.Warnings) == 0
	if status.Ready {
		status.Status = "READY"
	} else if len(associations) > 0 {
		status.Status = "DEGRADED"
	}
	return status, nil
}

func cloneRuntimeState(state AssociationRuntimeState) *AssociationRuntimeState {
	copy := state
	if state.NextIVCounter != nil {
		value := *state.NextIVCounter
		copy.NextIVCounter = &value
	}
	if state.ReplayHighest != nil {
		value := *state.ReplayHighest
		copy.ReplayHighest = &value
	}
	return &copy
}
