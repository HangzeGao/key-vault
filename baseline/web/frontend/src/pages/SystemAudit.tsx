import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Database, HardDrive, RefreshCw, ScrollText, ShieldCheck } from "lucide-react";
import { EmptyState, ErrorState, Loading, PageContainer, Panel, showToast } from "../components";
import { SignalPill, StatCard, StatusRow, formatBytes, formatCount, useDBStatus } from "../components/ops";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import type { AuditEvent, AuditVerifyResult } from "../lib/types";

function duration(milliseconds: number): string {
  return milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s`;
}

export function SystemAuditPage() {
  const client = useQueryClient();
  const database = useDBStatus();
  const verification = useQuery({
    queryKey: ["audit-chain-verify"],
    queryFn: () => api.get<{ results: AuditVerifyResult[] }>(apiPaths.audit.verify()),
    refetchInterval: 30_000,
  });
  const events = useQuery({
    queryKey: ["audit-events", "recent"],
    queryFn: () => api.get<{ events: AuditEvent[] }>(apiPaths.audit.events({ limit: 20 })),
    refetchInterval: 30_000,
  });
  const data = database.data;
  const chains = verification.data?.results ?? [];
  const recent = events.data?.events ?? [];
  const auditIntact = chains.every((chain) => chain.intact);
  const observed = data?.observed_at ? new Date(data.observed_at).toLocaleString("en-GB", { hour12: false }) : "Not observed";
  const totalBytes = (data?.storage.database_bytes ?? 0) + (data?.storage.wal_bytes ?? 0);
  const refresh = () => {
    client.invalidateQueries({ queryKey: ["ops", "db-status"] });
    client.invalidateQueries({ queryKey: ["audit-chain-verify"] });
    client.invalidateQueries({ queryKey: ["audit-events"] });
    showToast("System and audit status refreshed", "info");
  };

  return <PageContainer>
    <div className="page-header operations-header">
      <div>
        <div className="operations-kicker"><ShieldCheck size={13} />LOCAL ASSURANCE</div>
        <h1 className="section-title">System & Audit</h1>
        <p className="section-subtitle">Read-only SQLite health and hash-chain evidence for the single ground crypto process.</p>
      </div>
      <button className="operations-refresh" type="button" onClick={refresh}>
        <RefreshCw size={13} className={database.isFetching || verification.isFetching || events.isFetching ? "spinning" : ""} />Refresh status
      </button>
    </div>

    {database.isLoading && <Loading label="Loading system status..." />}
    {database.isError && <ErrorState message="System persistence status is unavailable." />}
    {data && <>
      <section className="ops-status-board compact">
        <div className="ops-status-primary"><Database size={25} /><div><span>System posture</span><strong>{data.status.toUpperCase()}</strong></div></div>
        <div className="ops-status-meta"><span>State</span><SignalPill label={data.connected ? "ONLINE" : "OFFLINE"} tone={data.connected ? "success" : "danger"} /></div>
        <div className="ops-status-meta"><span>Audit</span><strong>{verification.isError ? "UNAVAILABLE" : auditIntact ? "INTACT" : "BROKEN"}</strong></div>
        <div className="ops-status-meta observed"><span>Observed</span><strong>{observed}</strong></div>
      </section>
      <div className="grid-stats database-ops-stat-grid">
        <StatCard icon={<Activity />} label="Connection" value={data.connected ? duration(data.connection.latency_ms) : "OFFLINE"} sub={[]} />
        <StatCard icon={<HardDrive />} label="State size" value={formatBytes(totalBytes)} sub={[{ label: "WAL", value: formatBytes(data.storage.wal_bytes), color: "var(--accent)" }]} />
        <StatCard icon={<Database />} label="Associations" value={formatCount(data.records.security_associations)} sub={[{ label: "audit events", value: formatCount(data.records.audit_events), color: "var(--text-tertiary)" }]} />
        <StatCard icon={<ScrollText />} label="Audit chains" value={String(chains.length)} sub={[{ label: auditIntact ? "intact" : "attention required", value: "", color: auditIntact ? "var(--success)" : "var(--danger)" }]} />
      </div>
      <div className="ops-dashboard-grid">
        <Panel title="Durability">
          <StatusRow label="Journal mode" value={data.storage.journal_mode} ok={data.storage.journal_mode === "WAL"} />
          <StatusRow label="Commit synchronization" value={data.storage.synchronous} ok={data.storage.synchronous === "FULL"} />
          <StatusRow label="Integrity check" value={data.integrity.status} ok={data.integrity.status === "ok"} />
          <StatusRow label="Restore rule" value={data.backup.rule ?? "unavailable"} />
        </Panel>
        <Panel title="Audit Integrity">
          {verification.isError ? <ErrorState message="Audit verification is unavailable." /> : verification.isLoading ? <Loading label="Verifying audit chains..." /> : chains.length === 0 ? <EmptyState icon={<ShieldCheck />} message="No audit chains recorded" /> :
            <div className="compact-stack">{chains.map((chain) => <StatusRow key={chain.chain_name} label={chain.chain_name} value={chain.intact ? "INTACT" : `BROKEN @ ${chain.broken_seq ?? "?"}`} ok={chain.intact} />)}</div>}
        </Panel>
      </div>
      <Panel title={`Recent Audit Events / ${recent.length}`}>
        {events.isError ? <ErrorState message="Recent audit events are unavailable." /> : events.isLoading ? <Loading label="Loading audit events..." /> : recent.length === 0 ? <EmptyState icon={<ScrollText />} message="No audit events recorded" /> :
          <div className="table-scroll"><table className="data-table operations-table"><thead><tr><th>Sequence</th><th>Timestamp</th><th>Action</th><th>Result</th><th>Actor</th><th>Target</th></tr></thead><tbody>{recent.map((event) => <tr key={event.EventID}><td>{event.Sequence}</td><td>{new Date(event.Timestamp).toLocaleString("en-GB", { hour12: false })}</td><td>{event.Action}</td><td>{event.Result}</td><td>{event.ActorHash}</td><td>{event.TargetIDHash}</td></tr>)}</tbody></table></div>}
      </Panel>
    </>}
  </PageContainer>;
}
