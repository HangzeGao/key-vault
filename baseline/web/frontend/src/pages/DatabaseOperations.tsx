import { Activity, Database, HardDrive, RefreshCw, ShieldCheck } from "lucide-react";
import { ErrorState, Loading, PageContainer, Panel, showToast } from "../components";
import { DatabaseContent, SignalPill, StatCard, StatusRow, formatBytes, formatCount, useDBStatus } from "../components/ops";

function tone(status: "ok" | "warn" | "degraded" | "unknown" | undefined): "success" | "warning" | "danger" | "neutral" {
  if (status === "ok") return "success";
  if (status === "warn") return "warning";
  if (status === "degraded") return "danger";
  return "neutral";
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${Math.floor(milliseconds / 60_000)}m ${Math.floor((milliseconds % 60_000) / 1000)}s`;
}

function formatObservedAt(value?: string): string {
  if (!value) return "not observed";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function DatabaseOperationsPage() {
  const query = useDBStatus();
  const data = query.data;
  if (query.isLoading && !data) return <PageContainer><h1 className="section-title">Database Operations</h1><Loading label="loading database diagnostics..." /></PageContainer>;
  if (query.error && !data) return <PageContainer><h1 className="section-title">Database Operations</h1><ErrorState message={query.error.message} /></PageContainer>;

  const poolUtilization = data?.runtime.pool.max ? Math.round((data.runtime.pool.acquired / data.runtime.pool.max) * 100) : 0;
  const capacityAvailable = !data?.unavailable?.includes("capacity");
  const schemaReady = data?.runtime.schema.status === "ok";
  const integrity = data?.integrity;
  return (
    <PageContainer>
      <div className="dashboard-header">
        <div>
          <h1 className="section-title">Database Operations</h1>
          <p className="section-subtitle">Redacted runtime, capacity, protection, and domain-integrity diagnostics. No SQL console or record values are exposed.</p>
        </div>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => { query.refetch(); showToast("database diagnostics refreshed", "info"); }}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      <Panel>
        <div className="database-ops-summary">
          <div>
            <div className="dashboard-summary-title"><Database size={22} /><span>Repository readiness</span><SignalPill label={data?.status ?? "unknown"} tone={tone(data?.status)} /></div>
            <div className="dashboard-summary-sub">Observed {formatObservedAt(data?.observed_at)}. Diagnostics are read-only and globally aggregated for the Ops plane.</div>
          </div>
          <div className="database-ops-coverage"><span>Coverage</span><strong>{data?.unavailable?.length ? `${data.unavailable.length} unavailable` : "complete"}</strong></div>
        </div>
      </Panel>

      <div className="grid-stats database-ops-stat-grid">
        <StatCard icon={<Activity />} label="Connection" value={data?.connected ? formatDuration(data.connection.latency_ms) : "OFFLINE"} sub={[{ label: data?.connection.reason?.replaceAll("_", " ").toLowerCase() ?? data?.connection.status ?? "unknown", value: "", color: data?.connected ? "var(--success)" : "var(--danger)" }]} />
        <StatCard icon={<Database />} label="Role" value={(data?.runtime.role ?? "unknown").toUpperCase()} sub={[{ label: "pool used", value: `${poolUtilization}%`, color: poolUtilization >= 80 ? "var(--warning)" : "var(--accent)" }]} />
        <StatCard icon={<HardDrive />} label="Capacity" value={capacityAvailable ? formatBytes(data?.capacity.database_bytes) : "-"} sub={[{ label: "tables", value: formatCount(data?.capacity.tables.length), color: "var(--text-tertiary)" }]} />
        <StatCard icon={<ShieldCheck />} label="Schema" value={data ? `${data.runtime.schema.current}/${data.runtime.schema.expected}` : "-"} sub={[{ label: schemaReady ? "current" : "migration mismatch", value: "", color: schemaReady ? "var(--success)" : "var(--danger)" }]} />
      </div>

      <div className="dashboard-grid-2 database-ops-detail-grid">
        <Panel title="Runtime">
          <StatusRow label="Pool connections" value={`${data?.runtime.pool.acquired ?? 0} acquired / ${data?.runtime.pool.max ?? 0} max`} ok={poolUtilization < 80} />
          <StatusRow label="Idle connections" value={data?.runtime.pool.idle ?? 0} />
          <StatusRow label="Acquire wait events (cumulative)" value={data?.runtime.pool.acquire_wait_events ?? 0} />
          <StatusRow label="Active database sessions" value={data?.runtime.workload.active_connections ?? 0} />
          <StatusRow label="Lock waiters" value={data?.runtime.workload.lock_waiters ?? 0} ok={(data?.runtime.workload.lock_waiters ?? 0) === 0} />
          <StatusRow label="Transactions over 30s" value={data?.runtime.workload.long_transactions ?? 0} ok={(data?.runtime.workload.long_transactions ?? 0) === 0} />
          <StatusRow label="Oldest transaction" value={formatDuration(data?.runtime.workload.oldest_transaction_ms ?? 0)} />
        </Panel>
        <Panel title="Data Protection">
          <StatusRow label="Database role" value={data?.runtime.role ?? "unknown"} />
          <StatusRow label="Connected replicas" value={data?.data_protection.replica_count ?? 0} />
          <StatusRow label="Replication lag" value={formatDuration(data?.data_protection.replication_lag_ms ?? 0)} />
          <StatusRow label="Backup ownership" value={(data?.data_protection.backup_status ?? "unknown").replaceAll("_", " ")} />
          <div className="database-content-note">Backup success and restore drills must be reported by the external backup system; this service does not claim protection it cannot verify.</div>
        </Panel>
        <Panel title="Domain Integrity" action={<SignalPill label={integrity?.status ?? "unknown"} tone={tone(integrity?.status)} />}>
          <StatusRow label="Orphan key versions" value={integrity?.orphan_key_versions ?? 0} ok={(integrity?.orphan_key_versions ?? 0) === 0} />
          <StatusRow label="Destroyed rows retaining material" value={integrity?.destroyed_material_rows ?? 0} ok={(integrity?.destroyed_material_rows ?? 0) === 0} />
          <StatusRow label="Expired active DEK leases" value={integrity?.expired_active_dek_leases ?? 0} ok={(integrity?.expired_active_dek_leases ?? 0) === 0} />
          <StatusRow label="Expired active nonce leases" value={integrity?.expired_active_nonce_leases ?? 0} ok={(integrity?.expired_active_nonce_leases ?? 0) === 0} />
        </Panel>
        <Panel title="Diagnostic Coverage">
          {(data?.unavailable?.length ?? 0) === 0 ? <div className="dashboard-empty">All configured diagnostics are available.</div> : <div className="database-diagnostic-list">{data?.unavailable?.map((item) => <div className="record-card" key={item}><strong>{item.replaceAll("_", " ")}</strong><span>Unavailable to the current database role or backend.</span></div>)}</div>}
          <div className="database-content-note">Unavailable means “not observable”; it does not silently become a healthy zero.</div>
        </Panel>
      </div>

      <DatabaseContent capacity={data?.capacity} keyInventory={data?.key_inventory} capacityAvailable={capacityAvailable} backendRole={data?.runtime.role} />

      <div className="dashboard-section database-ops-boundary">
        <Panel title="Operations Boundary">
          <div className="dashboard-guidance"><div><ShieldCheck size={16} /><span>Recovery stays on audited, idempotent whitelist actions. Arbitrary SQL, record editing, secret export, migration-ledger changes, and destructive maintenance are intentionally unavailable.</span></div></div>
        </Panel>
      </div>
    </PageContainer>
  );
}
