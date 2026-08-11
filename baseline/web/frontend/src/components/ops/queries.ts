import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";

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
  schema: { status: "ok" | "degraded"; current: number; expected: number };
  storage: { database_bytes: number; wal_bytes: number; journal_mode: "WAL"; synchronous: "FULL" };
  records: { security_associations: number; audit_events: number };
  backup: { status: "operator_managed" | "unavailable"; rule?: string };
  integrity: { status: "ok" | "degraded" };
}

export interface CCSDSAssociationStatus {
  id: string;
  spi: number;
  direction: "TC_TX" | "TC_RECOVERY_TX" | "AOS_RX";
  state: "CURRENT" | "NEXT" | "ACTIVE";
  suite_id: string;
  security_epoch: number;
  key_version: number;
  policy_version: number;
  sequence_number_length: number;
  transmitted_iv_length: number;
  tag_length: number;
  replay_window: number;
  next_iv_counter?: number;
  replay_highest?: number;
  replay_seen: boolean;
}

export interface CCSDSOperationsStatus {
  observed_at: string;
  status: "READY" | "DEGRADED" | "UNCONFIGURED";
  ready: boolean;
  tc: {
    current: CCSDSAssociationStatus | null;
    next: CCSDSAssociationStatus | null;
    recovery: CCSDSAssociationStatus | null;
  };
  tc_rotation: {
    phase: "PREPARED" | "SWITCHING" | "ACTIVE";
    transaction_id: string;
    current_spi: number;
    next_spi: number;
    current_root_version: number;
    next_root_version: number;
    evidence: "RECOVERY_FRAME_PRODUCED" | "GROUND_PROMOTED" | "FIRST_NEXT_FRAME_PRODUCED";
  } | null;
  aos: CCSDSAssociationStatus[];
  warnings: string[];
}

export function useDBStatus(refetchInterval = 60_000) {
  return useQuery({
    queryKey: ["ops", "db-status"],
    queryFn: () => api.get<DBStatusResponse>(apiPaths.ops.dbStatus),
    refetchInterval,
  });
}

export function useCCSDSStatus(refetchInterval = 5_000) {
  return useQuery({
    queryKey: ["ops", "ccsds-status"],
    queryFn: async () => {
      const status = await api.get<CCSDSOperationsStatus>(apiPaths.ops.ccsdsStatus);
      if (!Array.isArray(status.warnings) || !Array.isArray(status.aos)) {
        throw new Error("invalid CCSDS operations response: warnings and aos must be arrays");
      }
      return status;
    },
    refetchInterval,
  });
}
