package nonce

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

// Golden Test Vectors for the GCM Nonce Lease protocol per design §8.2.
// These verify the domain derivation, nonce format, and lease semantics.

// TestGoldenNonceDomain verifies the domain derivation is deterministic and
// matches truncate32(SHA256(key_version_id || cluster_epoch || node_id)).
func TestGoldenNonceDomain(t *testing.T) {
	keyVersionID := "kv-001"
	clusterEpoch := uint64(42)
	nodeID := "node-1"

	got := Domain(keyVersionID, clusterEpoch, nodeID)

	// Manually compute expected domain.
	h := sha256.New()
	h.Write([]byte(keyVersionID))
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], clusterEpoch)
	h.Write(ep[:])
	h.Write([]byte(nodeID))
	sum := h.Sum(nil)
	want := binary.BigEndian.Uint32(sum[0:4])

	if got != want {
		t.Fatalf("domain = 0x%08x, want 0x%08x", got, want)
	}
}

// TestGoldenNonceDomainDeterminism verifies that the same inputs always produce
// the same domain.
func TestGoldenNonceDomainDeterminism(t *testing.T) {
	d1 := Domain("kv-1", 1, "node-a")
	d2 := Domain("kv-1", 1, "node-a")
	if d1 != d2 {
		t.Fatalf("domain not deterministic: %x vs %x", d1, d2)
	}
}

// TestGoldenNonceDomainDifferentInputs verifies that different inputs produce
// different domains (with high probability).
func TestGoldenNonceDomainDifferentInputs(t *testing.T) {
	d1 := Domain("kv-1", 1, "node-a")
	d2 := Domain("kv-2", 1, "node-a")
	d3 := Domain("kv-1", 2, "node-a")
	d4 := Domain("kv-1", 1, "node-b")
	if d1 == d2 {
		t.Fatal("domain collision on key_version_id")
	}
	if d1 == d3 {
		t.Fatal("domain collision on cluster_epoch")
	}
	if d1 == d4 {
		t.Fatal("domain collision on node_id")
	}
}

// TestGoldenNonceFormat verifies the 12-byte nonce layout: domain(4) || counter(8).
func TestGoldenNonceFormat(t *testing.T) {
	domain := uint32(0xDEADBEEF)
	counter := uint64(0x0102030405060708)
	n := FormatNonce(domain, counter)
	if len(n) != 12 {
		t.Fatalf("nonce len = %d, want 12", len(n))
	}
	gotDomain := binary.BigEndian.Uint32(n[0:4])
	gotCounter := binary.BigEndian.Uint64(n[4:12])
	if gotDomain != domain {
		t.Fatalf("domain = 0x%08x, want 0x%08x", gotDomain, domain)
	}
	if gotCounter != counter {
		t.Fatalf("counter = 0x%016x, want 0x%016x", gotCounter, counter)
	}
}

// TestGoldenNonceParse verifies ParseNonce round-trips with FormatNonce.
func TestGoldenNonceParse(t *testing.T) {
	domain := uint32(0xCAFEBABE)
	counter := uint64(0x1122334455667788)
	n := FormatNonce(domain, counter)
	gotDomain, gotCounter, err := ParseNonce(n)
	if err != nil {
		t.Fatalf("ParseNonce: %v", err)
	}
	if gotDomain != domain || gotCounter != counter {
		t.Fatalf("round-trip mismatch: domain=%x counter=%x", gotDomain, gotCounter)
	}
}

// TestGoldenNonceParseRejectsBadLength verifies that non-12-byte nonces are rejected.
func TestGoldenNonceParseRejectsBadLength(t *testing.T) {
	_, _, err := ParseNonce([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short nonce")
	}
}

// TestGoldenLeaseNextNonce verifies that NextNonce returns sequential counters
// in the domain || counter format.
func TestGoldenLeaseNextNonce(t *testing.T) {
	domain := uint32(0x12345678)
	l := &Lease{
		Domain:       domain,
		StartCounter: 100,
		EndCounter:   110,
		UsedCounter:  100,
		Status:       LeaseActive,
	}
	for i := uint64(0); i < 5; i++ {
		n, err := l.NextNonce()
		if err != nil {
			t.Fatalf("NextNonce[%d]: %v", i, err)
		}
		gotCounter := binary.BigEndian.Uint64(n[4:12])
		wantCounter := uint64(100) + i
		if gotCounter != wantCounter {
			t.Fatalf("counter[%d] = %d, want %d", i, gotCounter, wantCounter)
		}
		gotDomain := binary.BigEndian.Uint32(n[0:4])
		if gotDomain != domain {
			t.Fatalf("domain = %x, want %x", gotDomain, domain)
		}
	}
}

// TestGoldenLeaseExhaustion verifies that NextNonce returns ErrExhausted when
// the lease is fully consumed.
func TestGoldenLeaseExhaustion(t *testing.T) {
	l := &Lease{
		Domain:       1,
		StartCounter: 0,
		EndCounter:   3,
		UsedCounter:  0,
		Status:       LeaseActive,
	}
	// Consume all 3 counters.
	for i := 0; i < 3; i++ {
		if _, err := l.NextNonce(); err != nil {
			t.Fatalf("NextNonce[%d]: %v", i, err)
		}
	}
	// 4th call must fail.
	if _, err := l.NextNonce(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
}

// TestGoldenLeaseRemaining verifies the Remaining() calculation.
func TestGoldenLeaseRemaining(t *testing.T) {
	l := &Lease{
		StartCounter: 100,
		EndCounter:   200,
		UsedCounter:  150,
	}
	if l.Remaining() != 50 {
		t.Fatalf("Remaining = %d, want 50", l.Remaining())
	}
	if l.Used() != 50 {
		t.Fatalf("Used = %d, want 50", l.Used())
	}
	if l.Total() != 100 {
		t.Fatalf("Total = %d, want 100", l.Total())
	}
}

// TestGoldenLeaseWatermark verifies the watermark calculation.
func TestGoldenLeaseWatermark(t *testing.T) {
	l := &Lease{
		StartCounter: 0,
		EndCounter:   100,
		UsedCounter:  70,
	}
	if l.Watermark() != 0.70 {
		t.Fatalf("Watermark = %f, want 0.70", l.Watermark())
	}
}

// mockAllocator is a simple in-memory Allocator for testing.
type mockAllocator struct {
	mu       sync.Mutex
	next     uint64
	leases   map[string]*Lease
	used     map[string]uint64
	failNext bool
}

func newMockAllocator() *mockAllocator {
	return &mockAllocator{
		next:   0,
		leases: make(map[string]*Lease),
		used:   make(map[string]uint64),
	}
}

func (m *mockAllocator) AllocateRange(keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		return nil, errors.New("allocator: simulated failure")
	}
	start := m.next
	m.next += size
	leaseID := "lease-" + hex.EncodeToString(binary.BigEndian.AppendUint64(nil, start))
	l := &Lease{
		LeaseID:      leaseID,
		KeyVersionID: keyVersionID,
		NodeID:       nodeID,
		Domain:       domain,
		StartCounter: start,
		EndCounter:   start + size,
		UsedCounter:  start,
		ExpiresAt:    time.Now().Add(ttl),
		Status:       LeaseActive,
	}
	m.leases[leaseID] = l
	m.used[leaseID] = start
	return l, nil
}

func (m *mockAllocator) UpdateUsed(leaseID string, used uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.used[leaseID] = used
	return nil
}

func (m *mockAllocator) GetLease(leaseID string) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.leases[leaseID]
	if !ok {
		return nil, errors.New("not found")
	}
	return l, nil
}

// TestGoldenManagerGetLeaseForUse verifies that the manager returns an active lease.
func TestGoldenManagerGetLeaseForUse(t *testing.T) {
	alloc := newMockAllocator()
	mgr := NewManager(alloc, 1024, 0.70, 0.90, 5*time.Minute)

	l, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse: %v", err)
	}
	if l.Status != LeaseActive {
		t.Fatalf("status = %s, want ACTIVE", l.Status)
	}
	if l.Remaining() != 1024 {
		t.Fatalf("remaining = %d, want 1024", l.Remaining())
	}

	// Second call should return the same lease (cached).
	l2, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse[2]: %v", err)
	}
	if l2.LeaseID != l.LeaseID {
		t.Fatal("expected same lease on second call")
	}
}

// TestGoldenManagerNextNonce verifies that NextNonce returns sequential nonces.
func TestGoldenManagerNextNonce(t *testing.T) {
	alloc := newMockAllocator()
	mgr := NewManager(alloc, 1024, 0.70, 0.90, 5*time.Minute)

	l, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse: %v", err)
	}

	n1, err := mgr.NextNonce(l.LeaseID)
	if err != nil {
		t.Fatalf("NextNonce[1]: %v", err)
	}
	n2, err := mgr.NextNonce(l.LeaseID)
	if err != nil {
		t.Fatalf("NextNonce[2]: %v", err)
	}
	// Counters must differ by 1.
	c1 := binary.BigEndian.Uint64(n1[4:12])
	c2 := binary.BigEndian.Uint64(n2[4:12])
	if c2 != c1+1 {
		t.Fatalf("counters not sequential: %d -> %d", c1, c2)
	}
	// Domains must match.
	d1 := binary.BigEndian.Uint32(n1[0:4])
	d2 := binary.BigEndian.Uint32(n2[0:4])
	if d1 != d2 {
		t.Fatalf("domains differ: %x vs %x", d1, d2)
	}
}

// TestGoldenManagerFreezeNode verifies that a frozen node cannot get new leases.
func TestGoldenManagerFreezeNode(t *testing.T) {
	alloc := newMockAllocator()
	mgr := NewManager(alloc, 1024, 0.70, 0.90, 5*time.Minute)

	// Get a lease before freezing.
	l, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse: %v", err)
	}

	// Freeze the node.
	mgr.FreezeNode("node-1")
	if !mgr.IsFrozen("node-1") {
		t.Fatal("node should be frozen")
	}

	// Existing lease should still be usable.
	n, err := mgr.NextNonce(l.LeaseID)
	if err != nil {
		t.Fatalf("NextNonce after freeze: %v", err)
	}
	if n == nil {
		t.Fatal("nil nonce")
	}

	// But a NEW lease allocation for the frozen node must fail.
	// Use a different key version to force a new allocation.
	_, err = mgr.GetLeaseForUse("node-1", "kv-2", 1)
	if !errors.Is(err, ErrFrozen) {
		t.Fatalf("expected ErrFrozen, got %v", err)
	}

	// Unfreeze and retry.
	mgr.UnfreezeNode("node-1")
	if mgr.IsFrozen("node-1") {
		t.Fatal("node should not be frozen")
	}
	_, err = mgr.GetLeaseForUse("node-1", "kv-2", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse after unfreeze: %v", err)
	}
}

// TestGoldenManagerLeaseExhaustionAllocatesNew verifies that when a lease is
// exhausted, a new lease is allocated.
func TestGoldenManagerLeaseExhaustionAllocatesNew(t *testing.T) {
	alloc := newMockAllocator()
	// Small lease size to force exhaustion quickly.
	mgr := NewManager(alloc, 2, 0.70, 0.90, 5*time.Minute)

	l1, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse: %v", err)
	}
	// Consume both counters.
	if _, err := mgr.NextNonce(l1.LeaseID); err != nil {
		t.Fatalf("NextNonce[1]: %v", err)
	}
	if _, err := mgr.NextNonce(l1.LeaseID); err != nil {
		t.Fatalf("NextNonce[2]: %v", err)
	}

	// Next GetLeaseForUse should allocate a new lease.
	l2, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse[2]: %v", err)
	}
	if l2.LeaseID == l1.LeaseID {
		t.Fatal("expected new lease after exhaustion")
	}
	// New lease range must not overlap the old one.
	if l2.StartCounter < l1.EndCounter {
		t.Fatalf("new lease overlaps old: l2.start=%d l1.end=%d", l2.StartCounter, l1.EndCounter)
	}
}

// TestGoldenManagerWatermarks verifies the prefetch and throttle watermarks.
func TestGoldenManagerWatermarks(t *testing.T) {
	alloc := newMockAllocator()
	mgr := NewManager(alloc, 100, 0.70, 0.90, 5*time.Minute)

	l, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
	if err != nil {
		t.Fatalf("GetLeaseForUse: %v", err)
	}

	// Consume 50 counters (50%).
	for i := 0; i < 50; i++ {
		if _, err := mgr.NextNonce(l.LeaseID); err != nil {
			t.Fatalf("NextNonce[%d]: %v", i, err)
		}
	}
	if mgr.PrefetchNeeded(l) {
		t.Fatal("prefetch should not be needed at 50%")
	}
	if mgr.ThrottleNeeded(l) {
		t.Fatal("throttle should not be needed at 50%")
	}

	// Consume 20 more (70% total).
	for i := 0; i < 20; i++ {
		if _, err := mgr.NextNonce(l.LeaseID); err != nil {
			t.Fatalf("NextNonce[%d]: %v", i, err)
		}
	}
	if !mgr.PrefetchNeeded(l) {
		t.Fatal("prefetch should be needed at 70%")
	}
	if mgr.ThrottleNeeded(l) {
		t.Fatal("throttle should not be needed at 70%")
	}

	// Consume 20 more (90% total).
	for i := 0; i < 20; i++ {
		if _, err := mgr.NextNonce(l.LeaseID); err != nil {
			t.Fatalf("NextNonce[%d]: %v", i, err)
		}
	}
	if !mgr.PrefetchNeeded(l) {
		t.Fatal("prefetch should be needed at 90%")
	}
	if !mgr.ThrottleNeeded(l) {
		t.Fatal("throttle should be needed at 90%")
	}
}

// TestGoldenManagerConcurrent verifies the manager is safe for concurrent use.
func TestGoldenManagerConcurrent(t *testing.T) {
	alloc := newMockAllocator()
	mgr := NewManager(alloc, 1000, 0.70, 0.90, 5*time.Minute)

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := mgr.GetLeaseForUse("node-1", "kv-1", 1)
			if err != nil {
				errs <- err
				return
			}
			_, err = mgr.NextNonce(l.LeaseID)
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent error: %v", err)
	}
}
