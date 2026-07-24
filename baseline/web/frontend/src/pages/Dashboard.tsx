import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Activity, AlertTriangle, Boxes, Clock, Database, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { PageContainer, Panel, StatusPill, SuiteBadge, HashValue, Loading, ErrorState, showToast } from "../components";
import {
  Actions,
  Backlog,
  CRKPanel,
  HealthGrid,
  KeyStat,
  MetricStrip,
  SignalPill,
  StatCard,
  formatCount,
  formatUptime,
  useDBStatus,
  useHealth,
} from "../components/ops";
import type { AuditEvent, KeyDTO, LifecycleJob } from "../lib/types";

interface SystemStatus {
  database: { driver: string; connected: boolean; error?: string };
  server: { listen_addr: string; tpm_provider: string; plane_isolation: string; uptime_seconds: number };
  cluster: {
    cluster_epoch: number;
    crk?: { version: number; epoch: number; status: string; created: string };
    error?: string;
  };
  keys: { total: number; active: number; disabled: number; destroy_pending: number; destroyed: number };
  audit_chains?: Array<{ chain: string; sequence: number; head_hash: string; updated: string }>;
  lifecycle?: { pending: number; running: number; done: number; failed: number };
  nodes?: Array<{ node_id: string; role: string; status: string; cluster_epoch: number; attestation_epoch: number }>;
}

function stateTone(ok: boolean, warn = false): "success" | "warning" | "danger" {
  if (!ok) return "danger";
  return warn ? "warning" : "success";
}

function shortID(value: string, length = 16) {
  return value.length > length ? `${value.slice(0, length)}...` : value;
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function DashboardPage() {
  const { tenantId } = useAuth();
  const navigate = useNavigate();
  const [highlighted, setHighlighted] = useState<string | null>(null);

  const { data: status, isLoading: statusLoading, error: statusError, refetch: refetchStatus } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>(apiPaths.status),
    refetchInterval: 5000,
  });

  const { data: keysData, isLoading: keysLoading } = useQuery({
    queryKey: ["keys", tenantId],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keys),
  });

  const healthQ = useHealth();
  const dbQ = useDBStatus(30_000);
  const recentAuditQ = useQuery({ queryKey: ["dashboard", "audit", tenantId], queryFn: () => api.get<{ events: AuditEvent[] }>(apiPaths.audit.events({ limit: 8 })), retry: false });
  const recentLifecycleQ = useQuery({ queryKey: ["dashboard", "lifecycle", tenantId], queryFn: () => api.get<{ jobs: LifecycleJob[] }>(apiPaths.lifecycle.jobs({ limit: 8 })), retry: false });

  const keys = keysData?.keys ?? [];
  const recentKeys = useMemo(
    () => [...keys].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()).slice(0, 5),
    [keys],
  );

  const keyStats = status?.keys;
  const auditChains = status?.audit_chains ?? [];
  const auditTotal = auditChains.reduce((sum, chain) => sum + chain.sequence, 0);
  const backlog = dbQ.data?.backlog;
  const backlogTotal = (backlog?.lifecycle_failed ?? 0) + (backlog?.lifecycle_pending ?? 0) + (backlog?.outbox_pending ?? 0);
  const lifecycleOpen = (status?.lifecycle?.pending ?? 0) + (status?.lifecycle?.running ?? 0) + (status?.lifecycle?.failed ?? 0);
  const actionable = [
    (backlog?.lifecycle_failed ?? 0) > 0 && { label: `${backlog?.lifecycle_failed} failed lifecycle jobs`, href: "/ui/lifecycle" },
    (backlog?.outbox_pending ?? 0) > 0 && { label: `${backlog?.outbox_pending} pending outbox events`, href: "/ui/lifecycle" },
    dbQ.data?.crk_consistency?.digest_valid === false && { label: "CRK AAD digest is invalid", href: "#crk" },
    healthQ.data?.checks?.audit?.status === "degraded" && { label: "Audit chain health is degraded", href: "/ui/audit" },
  ].filter(Boolean) as Array<{ label: string; href: string }>;
  const recentHighRisk = (recentAuditQ.data?.events ?? []).filter((event) => /ops\.|destroy|policy|crk/i.test(event.Action)).slice(0, 5);
  const crkDigestValid = dbQ.data?.crk_consistency?.digest_valid;
  const databaseConnected = dbQ.data?.connected ?? status?.database.connected ?? false;
  const clusterReady = Boolean(databaseConnected && !status?.cluster.error);
  const nodeCount = status?.nodes?.length ?? 0;

  const criticalIssues = [healthQ.data?.overall === "degraded", dbQ.data?.status === "degraded", !databaseConnected, Boolean(status?.cluster.error), crkDigestValid === false];
  const warningIssues = [healthQ.data?.overall === "warn", dbQ.data?.status === "warn", (status?.lifecycle?.failed ?? 0) > 0, (backlog?.lifecycle_failed ?? 0) > 0];
  const issueCount = [...criticalIssues, ...warningIssues].filter(Boolean).length;
  const summaryTone = criticalIssues.some(Boolean) ? "danger" : warningIssues.some(Boolean) ? "warning" : stateTone(clusterReady);
  const summaryLabel = issueCount > 0 ? `${issueCount} item${issueCount > 1 ? "s" : ""} needs attention` : "operational";

  if (statusLoading && !status && dbQ.isLoading) {
    return (
      <PageContainer>
        <h1 className="section-title">Dashboard</h1>
        <Loading label="loading status..." />
      </PageContainer>
    );
  }

  if (statusError && !status && !dbQ.data) {
    return (
      <PageContainer>
        <h1 className="section-title">Dashboard</h1>
        <ErrorState message={statusError.message} />
      </PageContainer>
    );
  }

  return (
    <PageContainer>
      <div className="dashboard-header">
        <div>
          <h1 className="section-title">Dashboard</h1>
          <p className="section-subtitle">Ops plane status, key inventory, audit chain heads, and controlled recovery actions for tenant {tenantId}</p>
        </div>
        <div className="toolbar-row">
          <Link to="/ui/database" className="btn btn-ghost btn-sm"><Database size={13} /> Database operations</Link>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => {
              refetchStatus();
              healthQ.refetch();
              dbQ.refetch();
              showToast("dashboard refreshed", "info");
            }}
          >
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      <Panel>
        <div className="dashboard-summary">
          <div className="dashboard-summary-main">
            <ShieldCheck size={26} style={{ color: summaryTone === "success" ? "var(--success)" : summaryTone === "danger" ? "var(--danger)" : "var(--warning)" }} />
            <div>
              <div className="dashboard-summary-title">
                <span>System readiness</span>
                <SignalPill label={summaryLabel} tone={summaryTone} />
              </div>
              <div className="dashboard-summary-sub">
                Health is <strong>{healthQ.data?.overall ?? "unknown"}</strong>; database is <strong>{databaseConnected ? "connected" : "offline"}</strong>; CRK digest is <strong>{crkDigestValid === undefined ? "unknown" : crkDigestValid ? "valid" : "invalid"}</strong>.
              </div>
            </div>
          </div>
          <MetricStrip
            items={[
              { label: "Backlog", value: formatCount(backlogTotal), tone: backlogTotal > 0 ? "warning" : "success" },
              { label: "Lifecycle open", value: formatCount(lifecycleOpen), tone: lifecycleOpen > 0 ? "warning" : "success" },
              { label: "Audit events", value: formatCount(auditTotal), tone: "info" },
              { label: "Nodes", value: formatCount(nodeCount), tone: nodeCount > 0 ? "success" : "neutral" },
            ]}
          />
        </div>
      </Panel>

      <div className="grid-stats dashboard-stat-grid">
        <StatCard
          icon={<Activity />}
          label="Health"
          value={(healthQ.data?.overall ?? "unknown").toUpperCase()}
          sub={[
            { label: "checks", value: Object.keys(healthQ.data?.checks ?? {}).length, color: "var(--text-tertiary)" },
            { label: "uptime", value: healthQ.data ? formatUptime(healthQ.data.uptime_seconds) : "-", color: "var(--accent)" },
          ]}
        />
        <StatCard
          icon={<Database />}
          label="Database"
          value={(dbQ.data?.status ?? "unknown").toUpperCase()}
          sub={[
            { label: dbQ.data?.connected ? "connected" : "offline", value: "", color: dbQ.data?.connected ? "var(--success)" : "var(--danger)" },
            { label: "ms", value: dbQ.data?.connection.latency_ms ?? "-", color: "var(--text-tertiary)" },
          ]}
        />
        <StatCard
          icon={<Boxes />}
          label="Cluster"
          value={`E${dbQ.data?.cluster_epoch ?? status?.cluster.cluster_epoch ?? "-"}`}
          sub={[
            { label: "nodes", value: formatCount(nodeCount), color: nodeCount > 0 ? "var(--success)" : "var(--text-tertiary)" },
            { label: status?.cluster.error ? "attention" : "ready", value: "", color: status?.cluster.error ? "var(--danger)" : "var(--success)" },
          ]}
        />
        <StatCard
          icon={<ShieldCheck />}
          label="CRK"
          value={dbQ.data?.crk_consistency?.latest_version !== undefined ? `v${dbQ.data.crk_consistency.latest_version}` : status?.cluster.crk ? `v${status.cluster.crk.version}` : "-"}
          sub={[
            { label: status?.cluster.crk?.status ?? "not loaded", value: "", color: status?.cluster.crk?.status === "active" ? "var(--success)" : "var(--warning)" },
            { label: dbQ.data?.crk_consistency?.digest_valid === false ? "digest invalid" : dbQ.data?.crk_consistency?.digest_valid ? "digest valid" : "digest unknown", value: "", color: dbQ.data?.crk_consistency?.digest_valid === false ? "var(--danger)" : dbQ.data?.crk_consistency?.digest_valid ? "var(--success)" : "var(--text-tertiary)" },
          ]}
        />
        <StatCard
          icon={<KeyRound />}
          label="Keys"
          value={formatCount(keyStats?.total)}
          sub={[
            { label: "active", value: formatCount(keyStats?.active), color: "var(--success)" },
            { label: "disabled", value: formatCount(keyStats?.disabled), color: "var(--warning)" },
            { label: "destroy", value: formatCount(keyStats?.destroy_pending), color: "var(--danger)" },
          ]}
        />
        <StatCard
          icon={<Clock />}
          label="Server"
          value={status ? formatUptime(status.server.uptime_seconds) : "-"}
          sub={[
            { label: status?.server.tpm_provider ?? "tpm unknown", value: "", color: "var(--accent)" },
            { label: status?.server.plane_isolation ?? "", value: "", color: "var(--text-tertiary)" },
          ]}
        />
      </div>

      <div className="dashboard-section">
        <HealthGrid
          health={healthQ.data}
          isLoading={healthQ.isLoading}
          error={healthQ.error}
          highlighted={highlighted}
          onHighlight={setHighlighted}
        />
      </div>

      <div className="dashboard-grid-2">
        <Panel title="Actionable Items">
          {actionable.length ? <div className="compact-stack">{actionable.map((item) => <Link key={item.label} className="record-card" to={item.href}>{item.label}</Link>)}</div> : <div className="dashboard-empty">No immediate operational action is required.</div>}
        </Panel>
        <Panel title="Recent High-risk Activity" action={<Link to="/ui/audit" className="btn btn-ghost btn-sm">Audit</Link>}>
          {recentHighRisk.length === 0 && (recentLifecycleQ.data?.jobs ?? []).length === 0 ? <div className="dashboard-empty">No recent high-risk or lifecycle activity.</div> : <div className="compact-stack">{recentHighRisk.map((event) => <div className="record-card" key={event.EventID}><strong>{event.Action}</strong><span className="mono">{formatDate(event.Timestamp)} · {event.Result}</span></div>)}{(recentLifecycleQ.data?.jobs ?? []).slice(0, 3).map((job) => <div className="record-card" key={job.ID}><strong>{job.Type}</strong><span className="mono">{job.Status} · {formatDate(job.CreatedAt)}</span></div>)}</div>}
        </Panel>
      </div>

      <div className="dashboard-grid-main">
        <Panel title="Recent Keys" action={<Link to="/ui/keys" className="btn btn-ghost btn-sm">View all</Link>}>
          {keysLoading ? (
            <Loading label="loading keys..." />
          ) : recentKeys.length === 0 ? (
            <div className="dashboard-empty">No keys yet. Create one from the Keys page.</div>
          ) : (
            <div className="dashboard-table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Key ID</th>
                    <th>Suite</th>
                    <th>Version</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {recentKeys.map((key) => (
                    <tr key={key.key_id} onClick={() => navigate(`/ui/keys/${key.key_id}`)}>
                      <td>{key.name}</td>
                      <td className="mono">{shortID(key.key_id)}</td>
                      <td><SuiteBadge suite={key.suite_id} /></td>
                      <td className="mono">v{key.current_version}</td>
                      <td><StatusPill status={key.status} /></td>
                      <td className="mono">{formatDate(key.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Lifecycle Jobs">
          {status?.lifecycle ? (
            <div className="dashboard-lifecycle-grid">
              <KeyStat label="Pending" value={status.lifecycle.pending} color="var(--text-tertiary)" />
              <KeyStat label="Running" value={status.lifecycle.running} color="var(--accent)" />
              <KeyStat label="Done" value={status.lifecycle.done} color="var(--success)" />
              <KeyStat label="Failed" value={status.lifecycle.failed} color="var(--danger)" />
            </div>
          ) : (
            <div className="dashboard-empty">Lifecycle metrics are unavailable.</div>
          )}
        </Panel>
      </div>

      <div className="dashboard-grid-2">
        <Panel title="Audit Chain Heads">
          {auditChains.length > 0 ? (
            <div className="dashboard-table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Chain</th>
                    <th>Seq</th>
                    <th>Head Hash</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {auditChains.map((chain) => (
                    <tr key={chain.chain}>
                      <td className="mono">{chain.chain}</td>
                      <td className="mono">{chain.sequence}</td>
                      <td><HashValue value={chain.head_hash} label="audit chain head hash" /></td>
                      <td className="mono">{formatDate(chain.updated)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="dashboard-empty">No audit chain heads reported.</div>
          )}
        </Panel>

        <Panel title="Registered Nodes">
          {status?.nodes && status.nodes.length > 0 ? (
            <div className="dashboard-table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Node ID</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Epoch</th>
                  </tr>
                </thead>
                <tbody>
                  {status.nodes.map((node) => (
                    <tr key={node.node_id}>
                      <td className="mono">{shortID(node.node_id, 20)}</td>
                      <td className="mono">{node.role}</td>
                      <td><SignalPill label={node.status} tone={node.status === "ready" ? "success" : "warning"} /></td>
                      <td className="mono">{node.cluster_epoch}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="dashboard-empty">No registered nodes reported.</div>
          )}
        </Panel>
      </div>

      <div className="dashboard-section" id="crk">
        <CRKPanel />
      </div>

      <div className="dashboard-section">
        <Backlog />
      </div>

      <div className="dashboard-section">
        <Panel title="Operations Guide">
          <div className="dashboard-guidance">
            <div>
              <AlertTriangle size={16} />
              <span>Use controlled actions only after checking health, backlog, and audit chain status. Repair actions are audited by the ops plane.</span>
            </div>
          </div>
        </Panel>
      </div>

      <Actions />
    </PageContainer>
  );
}
