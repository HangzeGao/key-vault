import { Activity, Database, HardDrive, RefreshCw, ShieldCheck } from "lucide-react";
import { ErrorState, Loading, PageContainer, Panel, showToast } from "../components";
import { SignalPill, StatCard, StatusRow, formatBytes, formatCount, useDBStatus } from "../components/ops";

function duration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  return `${(milliseconds / 1000).toFixed(1)} s`;
}

export function DatabaseOperationsPage() {
  const query = useDBStatus();
  const data = query.data;
  if (query.isLoading && !data) return <PageContainer><h1 className="section-title">Security State</h1><Loading label="Loading SQLite diagnostics..." /></PageContainer>;
  if (query.error && !data) return <PageContainer><h1 className="section-title">Security State</h1><ErrorState message={query.error.message} /></PageContainer>;

  const observed = data?.observed_at ? new Date(data.observed_at).toLocaleString("en-GB", { hour12: false }) : "Not observed";
  const totalBytes = (data?.storage.database_bytes ?? 0) + (data?.storage.wal_bytes ?? 0);
  return (
    <PageContainer>
      <div className="page-header operations-header">
        <div>
          <div className="operations-kicker"><Database size={13} />LOCAL SECURITY STATE</div>
          <h1 className="section-title">Security State</h1>
          <p className="section-subtitle">Single-node SQLite health for associations, TC counters, AOS replay windows, TPM envelopes, and audit chains.</p>
        </div>
        <button type="button" className="operations-refresh" onClick={() => { query.refetch(); showToast("Security state diagnostics refreshed", "info"); }}>
          <RefreshCw size={13} className={query.isFetching ? "spinning" : ""} />Refresh diagnostics
        </button>
      </div>

      <section className="ops-status-board compact">
        <div className="ops-status-primary"><Database size={25} /><div><span>SQLite posture</span><strong>{data?.status?.toUpperCase() ?? "UNKNOWN"}</strong></div></div>
        <div className="ops-status-meta"><span>Connection</span><SignalPill label={data?.connected ? "ONLINE" : "OFFLINE"} tone={data?.connected ? "success" : "danger"} /></div>
        <div className="ops-status-meta"><span>Integrity</span><strong>{data?.integrity.status ?? "unknown"}</strong></div>
        <div className="ops-status-meta observed"><span>Observed</span><strong>{observed}</strong></div>
      </section>

      <div className="grid-stats database-ops-stat-grid">
        <StatCard icon={<Activity />} label="Connection" value={data?.connected ? duration(data.connection.latency_ms) : "OFFLINE"} sub={[{ label: data?.connected ? "local file" : data?.connection.reason ?? "unknown", value: "", color: data?.connected ? "var(--success)" : "var(--danger)" }]} />
        <StatCard icon={<HardDrive />} label="State size" value={formatBytes(totalBytes)} sub={[{ label: "WAL", value: formatBytes(data?.storage.wal_bytes), color: "var(--accent)" }]} />
        <StatCard icon={<Database />} label="Associations" value={formatCount(data?.records.security_associations)} sub={[{ label: "audit events", value: formatCount(data?.records.audit_events), color: "var(--text-tertiary)" }]} />
        <StatCard icon={<ShieldCheck />} label="Schema" value={data ? `${data.schema.current}/${data.schema.expected}` : "-"} sub={[{ label: data?.schema.status === "ok" ? "current" : "mismatch", value: "", color: data?.schema.status === "ok" ? "var(--success)" : "var(--danger)" }]} />
      </div>

      <div className="ops-dashboard-grid">
        <Panel title="Durability">
          <StatusRow label="Journal mode" value={data?.storage.journal_mode ?? "unknown"} ok={data?.storage.journal_mode === "WAL"} />
          <StatusRow label="Commit synchronization" value={data?.storage.synchronous ?? "unknown"} ok={data?.storage.synchronous === "FULL"} />
          <StatusRow label="Integrity check" value={data?.integrity.status ?? "unknown"} ok={data?.integrity.status === "ok"} />
          <p className="ops-panel-note">TC counter allocation and association transitions use immediate SQLite transactions and fail closed.</p>
        </Panel>
        <Panel title="Backup & Recovery">
          <StatusRow label="Backup ownership" value={(data?.backup.status ?? "unknown").replaceAll("_", " ")} />
          <StatusRow label="Restore rule" value={data?.backup.rule ?? "unavailable"} />
          <p className="ops-panel-note">Back up the database with SQLite online-backup semantics. Never resume transmission from a restored counter snapshot under the old SPI.</p>
        </Panel>
      </div>

      <Panel title="Persistence Boundary">
        <div className="ops-policy-grid">
          <div><ShieldCheck size={18} /><strong>Atomic state</strong><span>Security associations, TC IV allocation, AOS replay acceptance, and audit heads commit in one local store.</span></div>
          <div><Database size={18} /><strong>TPM boundary</strong><span>SQLite stores only TPM-sealed roots and wrapped protocol keys. Plaintext roots and working keys are never persisted.</span></div>
        </div>
      </Panel>
    </PageContainer>
  );
}
