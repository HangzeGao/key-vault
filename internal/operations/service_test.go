package operations

import (
	"context"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/domain/policy"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type fakeStore struct{ fail bool }

func (f fakeStore) Ping(context.Context) error {
	if f.fail {
		return errors.New("down")
	}
	return nil
}
func (f fakeStore) Diagnostics(context.Context) (*securitystate.Diagnostics, error) {
	if f.fail {
		return nil, errors.New("down")
	}
	return &securitystate.Diagnostics{Schema: 3, IntegrityOK: true, Associations: 3, AuditEvents: 2}, nil
}

type fakeResolver bool

func (f fakeResolver) Ready() bool { return bool(f) }

type fakePolicies struct{}

func (fakePolicies) Get(string) (*policy.Policy, error) { return &policy.Policy{}, nil }

type fakeTC struct{ ready bool }

func (f fakeTC) OperationsStatus(context.Context, string) (*protocol.OperationsStatus, error) {
	counter := uint64(4)
	return &protocol.OperationsStatus{Status: "READY", Ready: f.ready, TCCurrent: &protocol.AssociationRuntimeState{SPI: 1, NextIVCounter: &counter}, TCRotation: &protocol.TCRotationState{Phase: protocol.TCRotationPrepared, TransactionID: ^uint64(0)}, Warnings: []string{}}, nil
}

func TestSnapshotAggregatesReadyStateWithoutSecrets(t *testing.T) {
	counters := &access.Counters{}
	counters.RejectToken()
	service := New(Deps{Store: fakeStore{}, Resolver: fakeResolver(true), Policies: fakePolicies{}, TC: fakeTC{true}, Access: counters})
	value, err := service.Snapshot(context.Background(), "tenant")
	if err != nil || !value.Ready || value.Status != "READY" || value.TC.Current.SPI != 1 || value.TCRotation.TransactionID != "18446744073709551615" || value.AccessRejections.TokenRejected != 1 {
		t.Fatalf("value=%+v err=%v", value, err)
	}
	if value.Checks["downlink"].Status != "" {
		t.Fatalf("unsupported downlink check present: %+v", value)
	}
}
func TestSnapshotDegradesAcrossBoundaries(t *testing.T) {
	service := New(Deps{Store: fakeStore{true}, Resolver: fakeResolver(false), TC: fakeTC{false}})
	value, err := service.Snapshot(context.Background(), "tenant")
	if err != nil || value.Ready || value.Status != "DEGRADED" || value.Checks["state"].Status != "degraded" || value.Checks["policy"].Status != "degraded" {
		t.Fatalf("value=%+v err=%v", value, err)
	}
}
