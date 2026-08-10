package securitystate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/repository/models"
)

var _ auditchain.Store = (*Store)(nil)

func (s *Store) AppendAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	if event == nil || event.EventID == "" {
		return errors.New("securitystate: audit event id is required")
	}
	if event.ChainName == "" {
		event.ChainName = "system"
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Timestamp = event.Timestamp.UTC().Truncate(time.Microsecond)
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("securitystate: encode audit metadata: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin audit append", err)
	}
	defer tx.Rollback()
	now := formatTime(time.Now())
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_heads(chain_name,sequence,head_hash,updated_at)
		VALUES(?,0,'',?) ON CONFLICT(chain_name) DO NOTHING`, event.ChainName, now); err != nil {
		return wrap("ensure audit chain", err)
	}
	var sequence uint64
	if err := tx.QueryRowContext(ctx, `SELECT sequence,head_hash FROM audit_chain_heads WHERE chain_name=?`, event.ChainName).
		Scan(&sequence, &event.PrevHash); err != nil {
		return wrap("read audit chain head", err)
	}
	event.Sequence = sequence + 1
	canonical := canonicalAuditEvent(event)
	hash := sha256.New()
	hash.Write([]byte(event.PrevHash))
	hash.Write(canonical)
	event.CurrentHash = hex.EncodeToString(hash.Sum(nil))
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(event_id,request_id,tenant_hash,actor_type,actor_hash,
		action,target_type,target_id_hash,result,error_code,timestamp,metadata_json,chain_name,sequence,prev_hash,current_hash)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.EventID, event.RequestID, event.TenantHash, event.ActorType,
		event.ActorHash, event.Action, event.TargetType, event.TargetIDHash, event.Result, event.ErrorCode,
		formatTime(event.Timestamp), string(metadata), event.ChainName, event.Sequence, event.PrevHash, event.CurrentHash)
	if err != nil {
		return conflict("append audit event", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE audit_chain_heads SET sequence=?,head_hash=?,updated_at=?
		WHERE chain_name=? AND sequence=?`, event.Sequence, event.CurrentHash, now, event.ChainName, sequence)
	if err != nil {
		return wrap("advance audit chain", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("%w: audit chain changed concurrently", ErrConflict)
	}
	return wrap("commit audit append", tx.Commit())
}

func (s *Store) ListAuditEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT event_id,request_id,tenant_hash,actor_type,actor_hash,action,target_type,target_id_hash,
		result,error_code,timestamp,metadata_json,chain_name,sequence,prev_hash,current_hash FROM audit_events`
	var rows *sql.Rows
	var err error
	if chainName == "" {
		rows, err = s.db.QueryContext(ctx, query+` ORDER BY timestamp DESC,chain_name,sequence DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, query+` WHERE chain_name=? ORDER BY sequence DESC LIMIT ?`, chainName, limit)
	}
	if err != nil {
		return nil, wrap("list audit events", err)
	}
	defer rows.Close()
	var events []*models.AuditEvent
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, wrap("iterate audit events", rows.Err())
}

func scanAuditEvent(row rowScanner) (*models.AuditEvent, error) {
	var event models.AuditEvent
	var timestamp, metadata string
	if err := row.Scan(&event.EventID, &event.RequestID, &event.TenantHash, &event.ActorType, &event.ActorHash,
		&event.Action, &event.TargetType, &event.TargetIDHash, &event.Result, &event.ErrorCode, &timestamp, &metadata,
		&event.ChainName, &event.Sequence, &event.PrevHash, &event.CurrentHash); err != nil {
		return nil, wrap("scan audit event", err)
	}
	var err error
	event.Timestamp, err = parseTime(timestamp)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(metadata), &event.Metadata); err != nil {
		return nil, fmt.Errorf("securitystate: decode audit metadata: %w", err)
	}
	return &event, nil
}

func (s *Store) DeleteAuditEvents(ctx context.Context, chainName string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, wrap("begin audit delete", err)
	}
	defer tx.Rollback()
	var result sql.Result
	if chainName == "" {
		result, err = tx.ExecContext(ctx, `DELETE FROM audit_events`)
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM audit_chain_heads`)
		}
	} else {
		result, err = tx.ExecContext(ctx, `DELETE FROM audit_events WHERE chain_name=?`, chainName)
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM audit_chain_heads WHERE chain_name=?`, chainName)
		}
	}
	if err != nil {
		return 0, wrap("delete audit events", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, wrap("count deleted audit events", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, wrap("commit audit delete", err)
	}
	return int(count), nil
}

func (s *Store) GetAuditChainHead(ctx context.Context, chainName string) (*models.AuditChainHead, error) {
	var head models.AuditChainHead
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT chain_name,sequence,head_hash,updated_at FROM audit_chain_heads WHERE chain_name=?`, chainName).
		Scan(&head.ChainName, &head.Sequence, &head.HeadHash, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, wrap("get audit chain head", err)
	}
	head.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

func (s *Store) ListAuditChainHeads(ctx context.Context) ([]*models.AuditChainHead, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT chain_name,sequence,head_hash,updated_at FROM audit_chain_heads ORDER BY chain_name`)
	if err != nil {
		return nil, wrap("list audit chain heads", err)
	}
	defer rows.Close()
	var heads []*models.AuditChainHead
	for rows.Next() {
		var head models.AuditChainHead
		var updated string
		if err := rows.Scan(&head.ChainName, &head.Sequence, &head.HeadHash, &updated); err != nil {
			return nil, wrap("scan audit chain head", err)
		}
		head.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		heads = append(heads, &head)
	}
	return heads, wrap("iterate audit chain heads", rows.Err())
}

func (s *Store) VerifyAuditChain(ctx context.Context, chainName string) (uint64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,request_id,tenant_hash,actor_type,actor_hash,action,
		target_type,target_id_hash,result,error_code,timestamp,metadata_json,chain_name,sequence,prev_hash,current_hash
		FROM audit_events WHERE chain_name=? ORDER BY sequence`, chainName)
	if err != nil {
		return 0, wrap("verify audit chain", err)
	}
	defer rows.Close()
	var previous string
	var expected uint64 = 1
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return 0, err
		}
		if event.Sequence != expected {
			return event.Sequence, fmt.Errorf("audit sequence gap: expected %d got %d", expected, event.Sequence)
		}
		if event.PrevHash != previous {
			return event.Sequence, fmt.Errorf("audit previous hash mismatch at sequence %d", event.Sequence)
		}
		hash := sha256.New()
		hash.Write([]byte(previous))
		hash.Write(canonicalAuditEvent(event))
		if recomputed := hex.EncodeToString(hash.Sum(nil)); recomputed != event.CurrentHash {
			return event.Sequence, fmt.Errorf("audit hash mismatch at sequence %d", event.Sequence)
		}
		previous = event.CurrentHash
		expected++
	}
	return 0, wrap("iterate audit verification", rows.Err())
}

func canonicalAuditEvent(event *models.AuditEvent) []byte {
	parts := []string{event.EventID, event.RequestID, event.TenantHash, event.ActorType, event.ActorHash,
		event.Action, event.TargetType, event.TargetIDHash, event.Result, event.ErrorCode,
		formatTime(event.Timestamp), strconv.FormatUint(event.Sequence, 10), event.PrevHash}
	keys := make([]string, 0, len(event.Metadata))
	for key := range event.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+event.Metadata[key])
	}
	var output []byte
	for index, part := range parts {
		if index > 0 {
			output = append(output, '|')
		}
		output = append(output, part...)
	}
	return output
}
