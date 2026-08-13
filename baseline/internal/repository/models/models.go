// Package models defines the small persistent record set owned by SecurityState.
package models

import "time"

type KeyUsageScope string

const KeyUsageProtocol KeyUsageScope = "PROTOCOL"

// Key is a mission protocol root key. Plaintext material is never stored.
type Key struct {
	ID             string
	TenantID       string
	Name           string
	Purpose        string
	UsageScope     KeyUsageScope
	PolicyID       string
	SuiteID        string
	CurrentVersion uint32
	Status         string
	Tags           map[string]string
	ExpiresAt      time.Time
	ArchivedAt     time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// KeyVersion holds only direct TPM-sealed protocol key material.
type KeyVersion struct {
	ID             string
	KeyID          string
	VersionNo      uint32
	SuiteID        string
	SealedMaterial []byte
	Status         string
	CreatedAt      time.Time
}

// AuditEvent is an append-only event in a per-chain hash chain.
type AuditEvent struct {
	EventID      string
	RequestID    string
	TenantHash   string
	ActorType    string
	ActorHash    string
	Action       string
	TargetType   string
	TargetIDHash string
	Result       string
	ErrorCode    string
	Timestamp    time.Time
	Metadata     map[string]string
	ChainName    string
	Sequence     uint64
	PrevHash     string
	CurrentHash  string
}

type AuditChainHead struct {
	ChainName string
	Sequence  uint64
	HeadHash  string
	UpdatedAt time.Time
}
