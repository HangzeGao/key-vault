import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, Activity, Send, Clock, CheckCircle, XCircle, Loader } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { PageContainer, Panel, EmptyState, Loading, ErrorState, showToast } from "../components";
import type { LifecycleConfig, LifecycleJob, OutboxEvent } from "../lib/types";

const JOB_TYPE_LABEL: Record<string, string> = {
  key_expiry_check: "Key Expiry Scan",
  cache_invalidate: "Cache Invalidation",
  destroy_due: "Key Destruction",
  audit_forward: "Audit Forwarding",
};

const STATUS_STYLE: Record<string, { color: string; icon: typeof CheckCircle }> = {
  PENDING: { color: "var(--text-tertiary)", icon: Clock },
  RUNNING: { color: "var(--accent)", icon: Loader },
  DONE: { color: "var(--success)", icon: CheckCircle },
  FAILED: { color: "var(--danger)", icon: XCircle },
  SENT: { color: "var(--success)", icon: Send },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_STYLE[status] ?? STATUS_STYLE.PENDING;
  const Icon = cfg.icon;
  return (
    <span style={{ color: cfg.color, fontFamily: '"JetBrains Mono", monospace', fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}>
      <Icon size={12} /> {status}
    </span>
  );
}

function decodePayload(payload: number[] | undefined): string {
  if (!payload || payload.length === 0) return "{}";
  try {
    const bytes = new Uint8Array(payload);
    const text = new TextDecoder().decode(bytes);
    const redact = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(redact);
      if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /token|secret|plaintext|dek|crk|wrapped|envelope|ciphertext/i.test(key) ? "<redacted>" : redact(item)]));
      return value;
    };
    return JSON.stringify(redact(JSON.parse(text)), null, 2);
  } catch {
    return "(binary)";
  }
}

export function LifecyclePage() {
  const qc = useQueryClient();
  const [jobStatus, setJobStatus] = useState("");
  const [outboxStatus, setOutboxStatus] = useState("");
  const [outboxCollapsed, setOutboxCollapsed] = useState(false);
  const [jobCursor, setJobCursor] = useState(0);
  const [outboxCursor, setOutboxCursor] = useState(0);

  const { data: jobsData, isLoading: jobsLoading, error: jobsError } = useQuery({
    queryKey: ["lifecycle-jobs", jobStatus, jobCursor],
    queryFn: () => api.get<{ jobs: LifecycleJob[]; next_cursor?: string }>(apiPaths.lifecycle.jobs({ limit: 50, cursor: jobCursor, status: jobStatus || undefined })),
    refetchInterval: 5000,
  });
  const jobs = jobsData?.jobs ?? [];

  const { data: outboxData, isLoading: outboxLoading, error: outboxError } = useQuery({
    queryKey: ["lifecycle-outbox", outboxStatus, outboxCursor],
    queryFn: () => api.get<{ events: OutboxEvent[]; next_cursor?: string }>(apiPaths.lifecycle.outbox({ limit: 50, cursor: outboxCursor, status: outboxStatus || undefined })),
    refetchInterval: 5000,
  });
  const outbox = outboxData?.events ?? [];

  const { data: config, error: configError } = useQuery({
    queryKey: ["lifecycle-config"],
    queryFn: () => api.get<LifecycleConfig>(apiPaths.lifecycle.config),
  });

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["lifecycle-jobs"] });
    qc.invalidateQueries({ queryKey: ["lifecycle-outbox"] });
    showToast("refreshed", "info");
  };

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Lifecycle</h1>
          <p className="section-subtitle">Async worker, transactional outbox, and auto-refreshing job state</p>
        </div>
        <div className="page-header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      <div className="grid-2 page-section">
        {/* Jobs */}
        <Panel
          title="Lifecycle Jobs"
          action={
            <select className="select" style={{ width: "auto", fontSize: 11 }} value={jobStatus} onChange={(e) => { setJobStatus(e.target.value); setJobCursor(0); }}>
              <option value="">all</option>
              <option value="PENDING">pending</option>
              <option value="RUNNING">running</option>
              <option value="DONE">done</option>
              <option value="FAILED">failed</option>
            </select>
          }
        >
          {jobsError ? (
            <ErrorState message={jobsError.message} />
          ) : jobsLoading ? (
            <Loading label="loading jobs..." />
          ) : jobs.length === 0 ? (
            <EmptyState icon={<Activity />} message="no lifecycle jobs; worker scans every 5s, expiry scan every 60s" />
          ) : (
            <div className="compact-stack">
              {jobs.map((j) => (
                <div key={j.ID} className="record-card">
                  <div className="record-card-header">
                    <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, fontWeight: 600 }}>
                      {JOB_TYPE_LABEL[j.Type] ?? j.Type}
                    </span>
                    <StatusBadge status={j.Status} />
                  </div>
                  <div className="record-meta-grid">
                    <span>id: {j.ID.slice(0, 24)}...</span>
                    <span>attempt: {j.Attempt}</span>
                    {j.KeyID && <span>key: {j.KeyID.slice(0, 16)}...</span>}
                    {j.TenantID && <span>tenant: {j.TenantID}</span>}
                    <span>created: {new Date(j.CreatedAt).toLocaleTimeString()}</span>
                    {j.NextRunAt && j.Status !== "DONE" && <span>next: {new Date(j.NextRunAt).toLocaleTimeString()}</span>}
                  </div>
                  {j.IdempotencyKey && (
                    <div style={{ marginTop: 4, fontSize: 10, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)" }}>
                      idem: {j.IdempotencyKey}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          <div className="pagination-row"><button className="btn btn-ghost btn-sm" disabled={!jobCursor} onClick={() => setJobCursor(Math.max(0, jobCursor - 50))}>Previous</button><span className="mono">offset {jobCursor}</span><button className="btn btn-ghost btn-sm" disabled={!jobsData?.next_cursor} onClick={() => setJobCursor(Number(jobsData?.next_cursor))}>Next</button></div>
        </Panel>

        {/* Outbox */}
        <Panel
          title="Outbox Events"
          action={
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-ghost btn-sm" onClick={() => setOutboxCollapsed((v) => !v)}>
                {outboxCollapsed ? "Expand" : "Collapse"}
              </button>
              <select className="select" style={{ width: "auto", fontSize: 11 }} value={outboxStatus} onChange={(e) => { setOutboxStatus(e.target.value); setOutboxCursor(0); }}>
                <option value="">all</option>
                <option value="PENDING">pending</option>
                <option value="SENT">sent</option>
              </select>
            </div>
          }
        >
          {outboxError ? (
            <ErrorState message={outboxError.message} />
          ) : outboxLoading ? (
            <Loading label="loading outbox..." />
          ) : outboxCollapsed ? (
            <div className="mono" style={{ fontSize: 12, color: "var(--text-tertiary)", padding: 12 }}>
              {outbox.length} outbox events hidden
            </div>
          ) : outbox.length === 0 ? (
            <EmptyState icon={<Send />} message="no outbox events; triggered by key rotation, destroy scheduling, or policy reload" />
          ) : (
            <div className="compact-stack">
              {outbox.map((e) => (
                <div key={e.ID} className="record-card">
                  <div className="record-card-header">
                    <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, fontWeight: 600, color: "var(--accent)" }}>
                      {e.EventType}
                    </span>
                    <StatusBadge status={e.Status} />
                  </div>
                  <div style={{ fontSize: 11, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)", marginBottom: 4 }}>
                    aggregate: {e.AggregateID || "-"} / attempts: {e.Attempts}
                  </div>
                  <div style={{ fontSize: 10, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)" }}>
                    {new Date(e.CreatedAt).toLocaleTimeString()}
                  </div>
                  {e.Payload && e.Payload.length > 0 && (
                    <details style={{ marginTop: 6 }}>
                      <summary style={{ fontSize: 10, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)", cursor: "pointer" }}>
                        payload
                      </summary>
                      <button className="btn btn-ghost btn-sm" onClick={() => { navigator.clipboard.writeText(decodePayload(e.Payload)); showToast("copied redacted payload summary", "success"); }}>Copy redacted summary</button><pre className="payload-preview">
                        {decodePayload(e.Payload)}
                      </pre>
                    </details>
                  )}
                </div>
              ))}
            </div>
          )}
          <div className="pagination-row"><button className="btn btn-ghost btn-sm" disabled={!outboxCursor} onClick={() => setOutboxCursor(Math.max(0, outboxCursor - 50))}>Previous</button><span className="mono">offset {outboxCursor}</span><button className="btn btn-ghost btn-sm" disabled={!outboxData?.next_cursor} onClick={() => setOutboxCursor(Number(outboxData?.next_cursor))}>Next</button></div>
        </Panel>
      </div>

      <Panel title="Worker Configuration">
        {configError ? (
          <ErrorState message={configError.message} />
        ) : (
        <div className="config-strip">
          <div className="config-item">
            <div className="input-label">Owner</div>
            <div className="mono" style={{ fontSize: 11 }}>{config?.owner_id ?? "..."}</div>
          </div>
          <div className="config-item">
            <div className="input-label">Poll Interval</div>
            <div className="mono" style={{ fontSize: 11 }}>{config ? `${config.poll_interval} jobs/outbox / ${config.expiry_scan_interval} expiry` : "..."}</div>
          </div>
          <div className="config-item">
            <div className="input-label">Expiry Warning</div>
            <div className="mono" style={{ fontSize: 11 }}>{config?.expiry_warning_window ?? "..."}</div>
          </div>
          <div className="config-item">
            <div className="input-label">Lease TTL</div>
            <div className="mono" style={{ fontSize: 11 }}>{config?.lease_ttl ?? "..."}</div>
          </div>
          <div className="config-item">
            <div className="input-label">Max Attempts</div>
            <div className="mono" style={{ fontSize: 11 }}>{config ? `${config.max_attempts} (exponential backoff)` : "..."}</div>
          </div>
          <div className="config-item">
            <div className="input-label">Idempotency</div>
            <div className="mono" style={{ fontSize: 11, color: "var(--success)" }}>enabled</div>
          </div>
        </div>
        )}
      </Panel>
    </PageContainer>
  );
}
