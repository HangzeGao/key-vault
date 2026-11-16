package commissioning

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
)

type Phase byte

const (
	FactoryTest Phase = iota + 1
	TestClosing
	ReadyForCommissioning
	Commissioning
	InstalledLocked
	Operational
)

type Action byte

const (
	CloseTest Action = iota + 1
	ConfirmTestClosed
	BeginInstallation
	ConfirmInstallation
	ReleaseOperation
	InstallRoots
)

// Record is stored separately from test and operational key state. A platform
// must authenticate it and enforce anti-rollback across restarts and erasure.
type Record struct {
	Phase                 Phase
	TestTransaction       [32]byte
	ProductionTransaction [32]byte
}

var ErrLifecycle = errors.New("commissioning: denied lifecycle operation")

// Import uses the same trusted platform lock as Advance. The caller supplies
// a local, pinned recipient and issuer selected for the authorized purpose.
// Its installer must publish sealed state only under the verified transaction.
func Import(p Platform, binding Binding, e Envelope, recipient ecdh.KeyExchanger, issuer *ecdsa.PublicKey, evidence []byte, install func([]byte) error) error {
	if p == nil || len(evidence) == 0 {
		return ErrLifecycle
	}
	r, err := p.Load()
	if err != nil || !r.valid() {
		return ErrLifecycle
	}
	allowed := binding.Purpose == TestRoots && r.Phase == FactoryTest && binding.Transaction == r.TestTransaction
	if binding.Purpose == GroundRoots || binding.Purpose == FlightRoots {
		allowed = r.Phase == Commissioning && binding.Transaction == r.ProductionTransaction
	}
	if !allowed || p.Verify(InstallRoots, binding.Transaction, evidence) != nil {
		return ErrLifecycle
	}
	return open(binding, e, recipient, issuer, install)
}

func (r Record) valid() bool {
	if r.TestTransaction == ([32]byte{}) {
		return false
	}
	switch r.Phase {
	case FactoryTest, TestClosing, ReadyForCommissioning:
		return r.ProductionTransaction == ([32]byte{})
	case Commissioning, InstalledLocked, Operational:
		return r.ProductionTransaction != ([32]byte{}) && r.ProductionTransaction != r.TestTransaction
	default:
		return false
	}
}

// Permissions must be enforced while holding a platform lock that also guards
// Advance and in-flight maintenance work. Invalid state closes every path.
type Permissions struct {
	Test, ProductionImport, OperationalTC bool
}

func (r Record) Permissions() Permissions {
	if !r.valid() {
		return Permissions{}
	}
	return Permissions{Test: r.Phase == FactoryTest, ProductionImport: r.Phase == Commissioning, OperationalTC: r.Phase == Operational}
}

// Platform serializes callers across load, authorization and commit. Commit
// atomically replaces the expected authenticated record and verifies its
// durable anti-rollback anchor. Verify authenticates the actor and evidence
// for the action. In particular ConfirmTestClosed requires completed cleanup,
// revoked test access and a cold restart; ReleaseOperation requires durable
// installation, cold-restart key confirmation and the release authorization.
type Platform interface {
	Load() (Record, error)
	Verify(Action, [32]byte, []byte) error
	Commit(previous Record, next Record) error
}

// Advance moves forward by one state. Authorization and all platform errors
// are returned without exposing the opaque evidence or substrate error text.
func Advance(p Platform, action Action, transaction [32]byte, evidence []byte) error {
	if p == nil || transaction == ([32]byte{}) || len(evidence) == 0 {
		return ErrLifecycle
	}
	previous, err := p.Load()
	if err != nil || !previous.valid() {
		return ErrLifecycle
	}
	next := previous
	switch {
	case action == CloseTest && previous.Phase == FactoryTest && transaction == previous.TestTransaction:
		next.Phase = TestClosing
	case action == ConfirmTestClosed && previous.Phase == TestClosing && transaction == previous.TestTransaction:
		next.Phase = ReadyForCommissioning
	case action == BeginInstallation && previous.Phase == ReadyForCommissioning && transaction != previous.TestTransaction:
		next.Phase, next.ProductionTransaction = Commissioning, transaction
	case action == ConfirmInstallation && previous.Phase == Commissioning && transaction == previous.ProductionTransaction:
		next.Phase = InstalledLocked
	case action == ReleaseOperation && previous.Phase == InstalledLocked && transaction == previous.ProductionTransaction:
		next.Phase = Operational
	default:
		return ErrLifecycle
	}
	if p.Verify(action, transaction, evidence) != nil || p.Commit(previous, next) != nil {
		return ErrLifecycle
	}
	return nil
}
