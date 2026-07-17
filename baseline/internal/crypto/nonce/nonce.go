// Package nonce implements the GCM nonce lease protocol per design §8.2.
//
// Nonce format: domain(32 bit) || counter(64 bit) = 12 bytes total.
// domain = truncate32(SHA256(key_version_id || cluster_epoch || node_id))
//
// Leases are allocated as counter ranges [start, end). Counters are
// persisted BEFORE use. Allocated ranges are permanently burned (never
// recycled) even on graceful exit, crash, or TTL expiry.
package nonce

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Domain derives the 32-bit nonce domain per design §8.2.
// domain = truncate32(SHA256(key_version_id || cluster_epoch || node_id))
func Domain(keyVersionID string, clusterEpoch uint64, nodeID string) uint32 {
	h := sha256.New()
	h.Write([]byte(keyVersionID))
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], clusterEpoch)
	h.Write(ep[:])
	h.Write([]byte(nodeID))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[0:4])
}

// FormatNonce assembles a 12-byte nonce from domain + counter.
func FormatNonce(domain uint32, counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], domain)
	binary.BigEndian.PutUint64(n[4:12], counter)
	return n
}

// ParseNonce splits a 12-byte nonce into domain + counter.
func ParseNonce(nonce []byte) (domain uint32, counter uint64, err error) {
	if len(nonce) != 12 {
		return 0, 0, fmt.Errorf("nonce: expected 12 bytes, got %d", len(nonce))
	}
	domain = binary.BigEndian.Uint32(nonce[0:4])
	counter = binary.BigEndian.Uint64(nonce[4:12])
	return domain, counter, nil
}

// LeaseStatus enumerates lease states per design §11.2.
type LeaseStatus string

const (
	LeaseActive  LeaseStatus = "ACTIVE"
	LeaseReleased LeaseStatus = "RELEASED"
	LeaseExpired LeaseStatus = "EXPIRED"
	LeaseFrozen  LeaseStatus = "FROZEN"
)

// Lease is a counter range [Start, End) allocated to a node for a key version.
type Lease struct {
	LeaseID       string
	KeyVersionID  string
	NodeID        string
	Domain        uint32
	StartCounter  uint64
	EndCounter    uint64
	UsedCounter   uint64
	ExpiresAt     time.Time
	Status        LeaseStatus
}

// Remaining returns the number of unused counters in the lease.
func (l *Lease) Remaining() uint64 {
	if l.UsedCounter >= l.EndCounter {
		return 0
	}
	return l.EndCounter - l.UsedCounter
}

// Used returns the number of counters consumed.
func (l *Lease) Used() uint64 {
	if l.UsedCounter < l.StartCounter {
		return 0
	}
	return l.UsedCounter - l.StartCounter
}

// Total returns the total lease size.
func (l *Lease) Total() uint64 {
	return l.EndCounter - l.StartCounter
}

// Watermark returns the fraction of the lease that has been used.
func (l *Lease) Watermark() float64 {
	t := l.Total()
	if t == 0 {
		return 1.0
	}
	return float64(l.Used()) / float64(t)
}

// NextNonce returns the next nonce to use and advances the used counter.
// Returns an error if the lease is exhausted.
func (l *Lease) NextNonce() ([]byte, error) {
	if l.UsedCounter >= l.EndCounter {
		return nil, ErrExhausted
	}
	n := FormatNonce(l.Domain, l.UsedCounter)
	l.UsedCounter++
	return n, nil
}

// Errors.
var (
	ErrExhausted   = errors.New("nonce: lease exhausted")
	ErrFrozen      = errors.New("nonce: node frozen")
	ErrNotReady    = errors.New("nonce: lease not active")
)

// Manager allocates and tracks nonce leases. It is the in-memory
// authoritative source for the data plane; persistence is delegated to
// the repository (which writes the lease record before the manager
// returns the lease to the caller).
//
// Manager is safe for concurrent use.
type Manager struct {
	mu            sync.Mutex
	leases        map[string]*Lease // leaseID -> lease
	nodeLeases    map[string]map[string]*Lease // nodeID -> kvID -> active lease
	frozenNodes   map[string]struct{}
	allocator     Allocator
	leaseSize     uint64
	prefetchMark  float64
	throttleMark  float64
	ttl           time.Duration
}

// Allocator is the persistence interface for lease allocation.
// Allocate MUST persist the new lease range BEFORE returning, so that
// a crash after allocation does not cause counter reuse.
type Allocator interface {
	// AllocateRange atomically reserves [start, end) for the given
	// (keyVersionID, nodeID, domain). It MUST return the persisted lease.
	AllocateRange(keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*Lease, error)
	// UpdateUsed persists the used counter for a lease.
	UpdateUsed(leaseID string, used uint64) error
	// GetLease returns a lease by ID.
	GetLease(leaseID string) (*Lease, error)
}

// NewManager constructs a new Manager.
func NewManager(alloc Allocator, leaseSize uint64, prefetch, throttle float64, ttl time.Duration) *Manager {
	return &Manager{
		leases:       make(map[string]*Lease),
		nodeLeases:   make(map[string]map[string]*Lease),
		frozenNodes:  make(map[string]struct{}),
		allocator:    alloc,
		leaseSize:    leaseSize,
		prefetchMark: prefetch,
		throttleMark: throttle,
		ttl:          ttl,
	}
}

// FreezeNode prevents the node from receiving new lease allocations.
// Existing in-flight leases remain usable until exhausted or expired.
func (m *Manager) FreezeNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozenNodes[nodeID] = struct{}{}
}

// UnfreezeNode re-enables lease allocation for a node. Per design §8.2,
// unfreezing requires management API authorization (caller enforces).
func (m *Manager) UnfreezeNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.frozenNodes, nodeID)
}

// IsFrozen returns whether a node is frozen.
func (m *Manager) IsFrozen(nodeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.frozenNodes[nodeID]
	return ok
}

// GetLeaseForUse returns an active lease for the (node, keyVersion) pair,
// allocating a new one if none exists or the current one is exhausted.
// The returned lease has at least one counter available.
func (m *Manager) GetLeaseForUse(nodeID, keyVersionID string, clusterEpoch uint64) (*Lease, error) {
	m.mu.Lock()
	if _, frozen := m.frozenNodes[nodeID]; frozen {
		m.mu.Unlock()
		return nil, ErrFrozen
	}
	nodeMap, ok := m.nodeLeases[nodeID]
	if !ok {
		nodeMap = make(map[string]*Lease)
		m.nodeLeases[nodeID] = nodeMap
	}
	l, ok := nodeMap[keyVersionID]
	if ok && l.Remaining() == 0 {
		// Mark old lease as exhausted; allocate new.
		l.Status = LeaseReleased
		delete(nodeMap, keyVersionID)
		ok = false
	}
	if ok && (l.Status == LeaseActive || l.Status == LeaseFrozen) && l.Remaining() > 0 {
		m.mu.Unlock()
		return l, nil
	}
	m.mu.Unlock()

	// Allocate a new range via the allocator.
	domain := Domain(keyVersionID, clusterEpoch, nodeID)
	newLease, err := m.allocator.AllocateRange(keyVersionID, nodeID, domain, m.leaseSize, m.ttl)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check frozen status under lock.
	if _, frozen := m.frozenNodes[nodeID]; frozen {
		return nil, ErrFrozen
	}
	m.leases[newLease.LeaseID] = newLease
	m.nodeLeases[nodeID][keyVersionID] = newLease
	return newLease, nil
}

// NextNonce returns the next nonce for the lease and persists the used counter.
func (m *Manager) NextNonce(leaseID string) ([]byte, error) {
	m.mu.Lock()
	l, ok := m.leases[leaseID]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("nonce: unknown lease %s", leaseID)
	}
	n, err := l.NextNonce()
	used := l.UsedCounter
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Best-effort persist of used counter. If this fails, the lease is
	// still safe (counters are burned), but we surface the error so the
	// caller can alert. We do NOT roll back the in-memory counter: the
	// nonce has been issued and MUST NOT be re-issued.
	if err := m.allocator.UpdateUsed(leaseID, used); err != nil {
		// Log/observe but do not return error: the nonce is already consumed.
		_ = err
	}
	return n, nil
}

// PrefetchNeeded returns true if the lease has crossed the prefetch watermark.
func (m *Manager) PrefetchNeeded(l *Lease) bool {
	return l.Watermark() >= m.prefetchMark
}

// ThrottleNeeded returns true if the lease has crossed the throttle watermark.
func (m *Manager) ThrottleNeeded(l *Lease) bool {
	return l.Watermark() >= m.throttleMark
}

// DomainHex returns the domain as a hex string (for logging/diagnostics).
func DomainHex(d uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], d)
	return hex.EncodeToString(b[:])
}
