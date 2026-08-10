export interface ApiError {
  error: {
    code: string;
    message: string;
    retryable?: boolean;
  };
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
