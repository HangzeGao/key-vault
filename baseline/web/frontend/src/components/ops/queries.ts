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
  connected: boolean;
  cluster_epoch?: number;
  table_sizes?: Record<string, number>;
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
	error?: string;
	key_inventory?: {
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

export function useDBStatus() {
  return useQuery({
    queryKey: ["ops", "db-status"],
    queryFn: () => api.get<DBStatusResponse>(apiPaths.ops.dbStatus),
    refetchInterval: 5000,
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
