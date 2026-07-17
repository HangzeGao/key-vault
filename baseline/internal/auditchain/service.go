// Package auditchain implements the engineering baseline audit hash chain service.
//
// High-risk operations (CRK/Key lifecycle, node state, policy publish, destroy
// approval) write to the local WAL or same-transaction audit record BEFORE
// changing business state. Each event is canonicalized, then
// current_hash = H(prev_hash || canonical_event). Chains are per-tenant with
// monotonic sequence numbers tracked in audit_chain_heads.
//
// The verification tool detects deletion, truncation, reordering and field
// tampering. The baseline guarantees local chain integrity; external anchors are
// outside the current baseline.
package auditchain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

// Store is the repository subset used by the audit chain service.
type Store interface {
	AppendAuditEvent(ctx context.Context, e *models.AuditEvent) error
	ListAuditEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error)
	DeleteAuditEvents(ctx context.Context, chainName string) (int, error)
	GetAuditChainHead(ctx context.Context, chainName string) (*models.AuditChainHead, error)
	ListAuditChainHeads(ctx context.Context) ([]*models.AuditChainHead, error)
	VerifyAuditChain(ctx context.Context, chainName string) (brokenSeq uint64, err error)
}

// Service is the baseline audit chain service.
type Service struct {
	store Store
}

// New constructs an audit chain service.
func New(store Store) *Service {
	return &Service{store: store}
}

// RecordRequest is the input for recording an audit event.
type RecordRequest struct {
	EventID      string
	RequestID    string
	TenantID     string
	ActorType    string
	ActorHash    string
	Action       string
	TargetType   string
	TargetIDHash string
	Result       string
	ErrorCode    string
	Metadata     map[string]string
}

// Record appends a hash-chained audit event.
func (s *Service) Record(ctx context.Context, req RecordRequest) error {
	chainName := "system"
	if req.TenantID != "" {
		chainName = "tenant:" + req.TenantID
	}
	if req.EventID == "" {
		req.EventID = newID("aud")
	}
	e := &models.AuditEvent{
		EventID:      req.EventID,
		RequestID:    req.RequestID,
		TenantHash:   hashTruncate(req.TenantID),
		ActorType:    req.ActorType,
		ActorHash:    req.ActorHash,
		Action:       req.Action,
		TargetType:   req.TargetType,
		TargetIDHash: req.TargetIDHash,
		Result:       req.Result,
		ErrorCode:    req.ErrorCode,
		Timestamp:    time.Now().UTC(),
		Metadata:     req.Metadata,
		ChainName:    chainName,
	}
	return s.store.AppendAuditEvent(ctx, e)
}

// ListEvents returns audit events, optionally filtered by chain.
func (s *Service) ListEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.ListAuditEvents(ctx, chainName, limit)
}

// DeleteEvents deletes audit events for a chain, or all chains when chainName is empty.
func (s *Service) DeleteEvents(ctx context.Context, chainName string) (int, error) {
	return s.store.DeleteAuditEvents(ctx, chainName)
}

// ListChainHeads returns all chain heads (for monitoring).
func (s *Service) ListChainHeads(ctx context.Context) ([]*models.AuditChainHead, error) {
	return s.store.ListAuditChainHeads(ctx)
}

// VerifyResult is the outcome of a chain verification.
type VerifyResult struct {
	ChainName string `json:"chain_name"`
	Intact    bool   `json:"intact"`
	BrokenSeq uint64 `json:"broken_seq,omitempty"`
	Error     string `json:"error,omitempty"`
}

// VerifyChain verifies a single chain and returns the result.
func (s *Service) VerifyChain(ctx context.Context, chainName string) (*VerifyResult, error) {
	broken, err := s.store.VerifyAuditChain(ctx, chainName)
	if err != nil {
		return &VerifyResult{
			ChainName: chainName,
			Intact:    false,
			BrokenSeq: broken,
			Error:     err.Error(),
		}, nil
	}
	return &VerifyResult{
		ChainName: chainName,
		Intact:    true,
	}, nil
}

// VerifyAllChains verifies all known chains.
func (s *Service) VerifyAllChains(ctx context.Context) ([]*VerifyResult, error) {
	heads, err := s.store.ListAuditChainHeads(ctx)
	if err != nil {
		return nil, err
	}
	var results []*VerifyResult
	for _, h := range heads {
		r, _ := s.VerifyChain(ctx, h.ChainName)
		results = append(results, r)
	}
	return results, nil
}

// hashTruncate returns a truncated SHA-256 hash for privacy (design §15.1).
func hashTruncate(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func newID(prefix string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())))
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(h[:8]))
}
