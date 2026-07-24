import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";

export interface HealthCheck {
  status: string;
  summary: string;
  error?: string;
  detail?: Record<string, unknown>;
}
export interface HealthResponse {
  overall: string;
  uptime_seconds: number;
  checks: Record<string, HealthCheck>;
}

export interface DBStatusResponse {
  driver: string;
  status: "ok" | "warn" | "degraded";
  observed_at: string;
  connected: boolean;
  connection: {
    status: "ok" | "warn" | "degraded";
    reason?: string;
    latency_ms: number;
  };
  cluster_epoch?: number;
  runtime: {
    role: "primary" | "standby" | "memory" | "unknown";
    pool: { max: number; total: number; acquired: number; idle: number; acquire_wait_events: number };
    schema: { status: "ok" | "degraded"; current: number; expected: number };
    workload: { active_connections: number; lock_waiters: number; long_transactions: number; oldest_transaction_ms: number };
  };
  capacity: {
    database_bytes: number;
    tables: Array<{ name: string; estimated_rows: number; table_bytes: number; index_bytes: number; stats_updated_at?: string }>;
  };
  data_protection: { replica_count: number; replication_lag_ms: number; backup_status: "managed_externally" | "not_applicable" | string };
  integrity: {
    status: "ok" | "warn" | "degraded" | "unknown";
    orphan_key_versions: number;
    destroyed_material_rows: number;
    expired_active_dek_leases: number;
    expired_active_nonce_leases: number;
  };
  backlog: {
    lifecycle_failed: number;
    lifecycle_pending: number;
    outbox_pending: number;
  };
  crk_consistency?: {
    latest_version?: number;
    latest_version_id?: string;
    status?: string;
    digest_valid?: boolean;
    envelope_bytes?: number;
  };
	unavailable?: string[];
	key_inventory: {
		scope: "global" | "tenant";
		total: number;
		by_status: Record<string, number>;
		by_suite: Record<string, number>;
		by_purpose: Record<string, number>;
	};
}

export interface LifecycleJob {
  id: string;
  type: string;
  tenant_id: string;
  key_id: string;
  status: string;
  attempt: number;
  created_at: string;
  next_run_at?: string;
}

export interface OutboxEvent {
  id: string;
  event_type: string;
  aggregate_id: string;
  status: string;
  attempts: number;
  created_at: string;
}

export function useHealth() {
  return useQuery({
    queryKey: ["ops", "health"],
    queryFn: () => api.get<HealthResponse>(apiPaths.ops.health),
    refetchInterval: 5000,
  });
}

export function useDBStatus(refetchInterval = 60_000) {
  return useQuery({
    queryKey: ["ops", "db-status"],
    queryFn: () => api.get<DBStatusResponse>(apiPaths.ops.dbStatus),
    refetchInterval,
  });
}

export function useFailedLifecycleJobs() {
  return useQuery({
    queryKey: ["ops", "lifecycle", "failed"],
    queryFn: () => api.get<{ jobs: LifecycleJob[] }>(apiPaths.lifecycle.jobs({ status: "FAILED", limit: 50 })),
    refetchInterval: 5000,
  });
}

export function usePendingOutboxEvents() {
  return useQuery({
    queryKey: ["ops", "outbox", "pending"],
    queryFn: () => api.get<{ events: OutboxEvent[] }>(apiPaths.lifecycle.outbox({ status: "PENDING", limit: 50 })),
    refetchInterval: 5000,
  });
}
