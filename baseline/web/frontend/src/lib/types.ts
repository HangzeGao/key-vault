export interface KeyDTO {
  key_id: string;
  tenant_id: string;
  name: string;
  purpose: string;
  policy_id: string;
  suite_id: string;
  current_version: number;
  status: KeyStatus;
  tags?: Record<string, string>;
  expires_at?: string;
  archived_at?: string;
  created_at: string;
}

export type KeyStatus = "ACTIVE" | "EXPIRED" | "DISABLED" | "DESTROY_PENDING" | "DESTROYED";

export interface EncryptResponse {
  version: number;
  flags: number;
  key_id: string;
  key_version: number;
  suite_id: string;
  ciphertext: string;
  nonce?: string;
  tag?: string;
  aad_hash?: string;
  policy_version?: number;
  envelope_format?: string;
}

export interface DecryptResponse {
  key_id: string;
  key_version: number;
  plaintext: string;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    retryable?: boolean;
  };
}

export interface CreateKeyReq {
  tenant_id: string;
  key_id?: string;
  name: string;
  purpose: string;
  policy_id: string;
  suite_id: string;
  tags?: Record<string, string>;
  expires_at?: string;
}

export interface ImportKeyReq {
  tenant_id: string;
  key_id?: string;
  name: string;
  purpose: string;
  policy_id: string;
  suite_id: string;
  tags?: Record<string, string>;
  expires_at?: string;
  external_dek: string; // base64-encoded plaintext DEK
}

export interface BatchImportKeyResult {
  index: number;
  success: boolean;
  key?: KeyDTO;
  error_code?: string;
  message?: string;
}

export type EnvelopeJSON = Record<string, unknown>;

export interface TenantEnvelopeConfig {
  tenant_id: string;
  default_format: string;
  allowed_formats: string[];
  profiles?: EnvelopeFormatProfile[];
  aad_required: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  updated_by: string;
}

export interface EnvelopeFormatDescription {
  format_id: string;
  description: string;
  match_rule: string;
}

export interface EnvelopeFormatProfile {
  format_id: string;
  adapter: string;
  field_mappings?: EnvelopeFieldMapping[];
  extensions?: EnvelopeExtension[];
  description?: string;
}

export interface EnvelopeFieldMapping {
  path: string;
  source: string;
  required: boolean;
  encoding?: string;
  default_value?: string;
}

export interface EnvelopeExtension {
  name: string;
  type: string;
  required: boolean;
  default_value?: string;
  description?: string;
}

export interface AuditEvent {
  EventID: string;
  RequestID: string;
  TenantHash: string;
  ActorType: string;
  ActorHash: string;
  Action: string;
  TargetType: string;
  TargetIDHash: string;
  Result: string;
  ErrorCode: string;
  Timestamp: string;
  Metadata: Record<string, string>;
  ChainName: string;
  Sequence: number;
  PrevHash: string;
  CurrentHash: string;
}

export interface AuditChainHead {
  ChainName: string;
  Sequence: number;
  HeadHash: string;
  UpdatedAt: string;
}

export interface AuditVerifyResult {
  chain_name: string;
  intact: boolean;
  broken_seq?: number;
  error?: string;
}

export interface LifecycleJob {
  ID: string;
  Type: string;
  TenantID: string;
  KeyID: string;
  KeyVersionID: string;
  Payload: number[];
  Status: string;
  Attempt: number;
  NextRunAt: string;
  LeaseOwner: string;
  LeaseUntil: string;
  IdempotencyKey: string;
  CreatedAt: string;
  UpdatedAt: string;
}

export interface LifecycleConfig {
  owner_id: string;
  lease_ttl: string;
  max_attempts: number;
  poll_interval: string;
  expiry_scan_interval: string;
  expiry_warning_window: string;
}

export interface OutboxEvent {
  ID: string;
  EventType: string;
  AggregateID: string;
  Payload: number[];
  Status: string;
  Attempts: number;
  NextRunAt: string;
  CreatedAt: string;
}

export interface PolicySuite {
  suite_id: string;
  algorithm: string;
  key_bits: number;
  mode: string;
  nonce?: string;
  mac?: string;
  composition?: string;
  status: string;
  compliance?: string[];
}

export interface SignedPolicy {
  policy_id: string;
  version: number;
  effective_at: string;
  status: string;
  default_suite: string;
  suites: PolicySuite[];
  cryptoperiod: {
    default_days: number;
    max_days: number;
    rotate_before_days: number;
  };
  gray_rules: {
    tenant_allowlist?: string[];
    key_allowlist?: string[];
  };
  signature: {
    alg: string;
    key_id: string;
    sig: string;
    payload_hash: string;
  };
}

export interface BatchResult {
  index: number;
  success: boolean;
  error_code?: string;
  message?: string;
  key_id?: string;
  key_version?: number;
  suite_id?: string;
  envelope?: EnvelopeJSON;
  plaintext?: string;
}
