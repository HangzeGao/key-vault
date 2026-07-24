// Package audit implements structured audit events and the local WAL
// skeleton per design §15.1 and HA-07.
//
// Baseline WAL requirements:
//   - WAL file is independent of the business database.
//   - Append-only + fsync before returning.
//   - WAL write failure for high-risk operations => fail-closed.
//   - WAL records contain: event_id, action, target_hash, actor_hash,
//     timestamp, request_id, prev_wal_hash (may be empty).
//   - WAL files rotate by size; retention covers at least one recovery
//     drill window.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is a structured audit event per design §15.1.
type Event struct {
	EventID      string            `json:"event_id"`
	RequestID    string            `json:"request_id"`
	TenantHash   string            `json:"tenant_hash"`
	ActorType    string            `json:"actor_type"`
	ActorHash    string            `json:"actor_hash"`
	Action       string            `json:"action"`
	TargetType   string            `json:"target_type"`
	TargetIDHash string            `json:"target_id_hash"`
	Result       string            `json:"result"`
	ErrorCode    string            `json:"error_code,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// WALEntry is a high-risk operation WAL record per design §15.1.
type WALEntry struct {
	EventID     string    `json:"event_id"`
	Action      string    `json:"action"`
	TargetHash  string    `json:"target_hash"`
	ActorHash   string    `json:"actor_hash"`
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id"`
	PrevWALHash string    `json:"prev_wal_hash"` // may be empty in local baseline runs
}

// Sink is the interface for persisting audit events.
type Sink interface {
	Record(ctx context.Context, e *Event) error
}

// WAL is the append-only write-ahead log for high-risk operations.
type WAL interface {
	Append(ctx context.Context, e *WALEntry) error
	Close() error
}

// HighRiskAction enumerates actions that require WAL pre-write per HA-07.
type HighRiskAction string

const (
	HRCreateCRK          HighRiskAction = "crk.create"
	HRNodeRegister       HighRiskAction = "node.register"
	HRNodeRevoke         HighRiskAction = "node.revoke"
	HRKeyDestroy         HighRiskAction = "key.destroy"
	HRPolicyDowngrade    HighRiskAction = "policy.downgrade"
	HRClusterEpochChange HighRiskAction = "cluster_epoch.changed"
)

// IsHighRisk returns whether an action requires WAL pre-write.
func IsHighRisk(action string) bool {
	switch HighRiskAction(action) {
	case HRCreateCRK, HRNodeRegister, HRNodeRevoke, HRKeyDestroy,
		HRPolicyDowngrade, HRClusterEpochChange:
		return true
	}
	return false
}

// FileWAL is a file-based append-only WAL.
type FileWAL struct {
	mu          sync.Mutex
	dir         string
	maxSize     int64
	current     *os.File
	currentSize int64
	currentName string
	prevHash    string
}

// NewFileWAL opens or creates a WAL in dir.
func NewFileWAL(dir string, maxSize int64) (*FileWAL, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: mkdir: %w", err)
	}
	w := &FileWAL{dir: dir, maxSize: maxSize}
	if err := w.rotate(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *FileWAL) rotate() error {
	if w.current != nil {
		if err := w.current.Close(); err != nil {
			return fmt.Errorf("wal: close: %w", err)
		}
	}
	name := fmt.Sprintf("wal-%d.log", time.Now().UnixNano())
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("wal: open: %w", err)
	}
	w.current = f
	w.currentName = name
	w.currentSize = 0
	return nil
}

// Append writes a WAL entry with fsync. Returns error if write fails
// (caller MUST fail-closed).
func (w *FileWAL) Append(ctx context.Context, e *WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.currentSize >= w.maxSize {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	e.PrevWALHash = w.prevHash
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("wal: marshal: %w", err)
	}
	// Compute current hash = SHA-256(prevHash || entry).
	h := sha256.New()
	h.Write([]byte(w.prevHash))
	h.Write(b)
	curHash := hex.EncodeToString(h.Sum(nil))
	line := append(b, '\n')
	if _, err := w.current.Write(line); err != nil {
		return fmt.Errorf("wal: write: %w", err)
	}
	if err := w.current.Sync(); err != nil {
		return fmt.Errorf("wal: fsync: %w", err)
	}
	w.currentSize += int64(len(line))
	w.prevHash = curHash
	return nil
}

// Close closes the current WAL file.
func (w *FileWAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		err := w.current.Close()
		w.current = nil
		return err
	}
	return nil
}

// Replay reads all WAL entries in order. Used by the recovery tool.
func (w *FileWAL) Replay() ([]*WALEntry, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("wal: readdir: %w", err)
	}
	var out []*WALEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(w.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("wal: read %s: %w", path, err)
		}
		// Split by newline.
		start := 0
		for start < len(b) {
			end := start
			for end < len(b) && b[end] != '\n' {
				end++
			}
			if end == start {
				break
			}
			var entry WALEntry
			if err := json.Unmarshal(b[start:end], &entry); err != nil {
				return nil, fmt.Errorf("wal: parse %s: %w", path, err)
			}
			out = append(out, &entry)
			start = end + 1
		}
	}
	return out, nil
}

// ErrWALUnavailable is returned when the WAL cannot be written.
var ErrWALUnavailable = errors.New("audit: WAL unavailable")

// NoopWAL is a WAL that does nothing. Use ONLY in tests where high-risk
// operations are not exercised.
type NoopWAL struct{}

func (NoopWAL) Append(ctx context.Context, e *WALEntry) error { return nil }
func (NoopWAL) Close() error                                  { return nil }

// BufferedSink buffers events in memory and flushes asynchronously.
// The baseline allows audit to be eventually consistent for non-high-risk events.
type BufferedSink struct {
	mu     sync.Mutex
	events []*Event
}

// NewBufferedSink constructs a sink with the given buffer size.
func NewBufferedSink(size int) *BufferedSink {
	return &BufferedSink{events: make([]*Event, 0, size)}
}

// Record appends an event to the buffer.
func (s *BufferedSink) Record(ctx context.Context, e *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// Events returns a snapshot of buffered events.
func (s *BufferedSink) Events() []*Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Event, len(s.events))
	copy(out, s.events)
	return out
}

// Service is the audit service that coordinates the sink and WAL.
type Service struct {
	sink Sink
	wal  WAL
}

// NewService constructs an audit service.
func NewService(sink Sink, wal WAL) *Service {
	return &Service{sink: sink, wal: wal}
}

// Record writes a structured event to the sink. For high-risk actions,
// the WAL is written FIRST (fail-closed); only then is the event recorded.
func (s *Service) Record(ctx context.Context, e *Event) error {
	if IsHighRisk(e.Action) {
		wEntry := &WALEntry{
			EventID:    e.EventID,
			Action:     e.Action,
			TargetHash: e.TargetIDHash,
			ActorHash:  e.ActorHash,
			Timestamp:  e.Timestamp,
			RequestID:  e.RequestID,
		}
		if err := s.wal.Append(ctx, wEntry); err != nil {
			// Fail-closed: high-risk operation must not proceed.
			return fmt.Errorf("%w: %v", ErrWALUnavailable, err)
		}
	}
	return s.sink.Record(ctx, e)
}

// WAL returns the underlying WAL (for inspection/replay).
func (s *Service) WAL() WAL { return s.wal }
