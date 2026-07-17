import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ScrollText, AlertTriangle, RefreshCw, ShieldCheck, ShieldAlert, Link2, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { PageContainer, Panel, EmptyState, ErrorState, HashValue, Loading, showToast } from "../components";
import type { AuditEvent, AuditChainHead, AuditVerifyResult } from "../lib/types";

const HIGH_RISK_ACTIONS = [
  "CREATE_CRK", "DESTROY_CRK", "ROTATE_CRK", "SCHEDULE_DESTROY",
   "ALLOCATE_NONCE_RANGE",  "policy.reload",
];

const RESULT_COLOR: Record<string, string> = {
  success: "var(--success)",
  failure: "var(--danger)",
  denied: "var(--warning)",
};

export function AuditPage() {
  const qc = useQueryClient();
  const [chainFilter, setChainFilter] = useState("");
  const [limit, setLimit] = useState(100);
  const [cursor, setCursor] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [resultFilter, setResultFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [fromFilter, setFromFilter] = useState("");
  const [toFilter, setToFilter] = useState("");

  // Fetch audit events.
  const { data: eventsData, isLoading: eventsLoading, error: eventsError } = useQuery({
    queryKey: ["audit-events", chainFilter, limit, cursor, actionFilter, resultFilter, actorFilter, targetFilter, fromFilter, toFilter],
    queryFn: () =>
      api.get<{ events: AuditEvent[]; next_cursor?: string }>(apiPaths.audit.events({ limit, cursor, chain: chainFilter || undefined, action: actionFilter || undefined, result: resultFilter || undefined, actor: actorFilter || undefined, target: targetFilter || undefined, from: fromFilter ? new Date(fromFilter).toISOString() : undefined, to: toFilter ? new Date(toFilter).toISOString() : undefined })),
  });
  const events = eventsData?.events ?? [];

  // Fetch chain heads.
  const { data: headsData, error: headsError } = useQuery({
    queryKey: ["audit-chain-heads"],
    queryFn: () => api.get<{ heads: AuditChainHead[] }>(apiPaths.audit.heads),
    refetchInterval: 10000,
  });
  const heads = headsData?.heads ?? [];

  // Verify all chains.
  const { data: verifyData, isLoading: verifying, error: verifyError, refetch } = useQuery({
    queryKey: ["audit-chain-verify"],
    queryFn: () => api.get<{ results: AuditVerifyResult[] }>(apiPaths.audit.verify()),
    refetchInterval: 30000,
  });
  const verifyResults = verifyData?.results ?? [];

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["audit-events"] });
    qc.invalidateQueries({ queryKey: ["audit-chain-heads"] });
    refetch();
    showToast("audit refreshed", "info");
  };

  const deleteMut = useMutation({
    mutationFn: () => api.delete<{ deleted: number }>(apiPaths.audit.events({ chain: chainFilter || undefined })),
    onSuccess: (r) => {
      refresh();
      showToast(`deleted ${r.deleted} audit events`, "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const deleteCurrent = () => {
    const scope = chainFilter ? `chain ${chainFilter}` : "all chains";
    if (confirm(`Delete audit events for ${scope}? This resets affected chain heads.`)) {
      deleteMut.mutate();
    }
  };

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Audit Log</h1>
          <p className="section-subtitle">Hash-chained audit events with tamper detection and per-tenant chains</p>
        </div>
        <div className="page-header-actions">
          <button className="btn btn-ghost btn-sm" onClick={refresh}>
            <RefreshCw size={12} /> Refresh
          </button>
          <button className="btn btn-secondary btn-sm" disabled={deleteMut.isPending} onClick={deleteCurrent}>
            <Trash2 size={12} /> Delete
          </button>
        </div>
      </div>

      <div className="page-section">
      <Panel title="Chain Integrity Verification">
        {verifyError ? (
          <ErrorState message={verifyError.message} />
        ) : verifying ? (
          <Loading label="verifying chains..." />
        ) : verifyResults.length === 0 ? (
          <EmptyState icon={<ShieldCheck />} message="no chains to verify; perform operations to generate audit events" />
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {verifyResults.map((r) => (
              <div
                key={r.chain_name}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 14px",
                  background: "var(--bg-inset)",
                  border: `1px solid ${r.intact ? "var(--success)" : "var(--danger)"}`,
                  borderRadius: 2,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  {r.intact ? (
                    <ShieldCheck size={15} style={{ color: "var(--success)" }} />
                  ) : (
                    <ShieldAlert size={15} style={{ color: "var(--danger)" }} />
                  )}
                  <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{r.chain_name}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  {r.intact ? (
                    <span style={{ color: "var(--success)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>
                      intact
                    </span>
                  ) : (
                    <span style={{ color: "var(--danger)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>
                      broken @ seq {r.broken_seq} / {r.error}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
      </div>

      {/* Chain heads */}
      {headsError ? (
        <div className="page-section">
          <Panel title="Chain Heads">
            <ErrorState message={headsError.message} />
          </Panel>
        </div>
      ) : heads.length > 0 && (
        <div className="page-section">
        <Panel title="Chain Heads">
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Chain</th>
                  <th>Sequence</th>
                  <th>Head Hash</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {heads.map((h) => (
                  <tr key={h.ChainName}>
                    <td className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{h.ChainName}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{h.Sequence}</td>
                    <td><HashValue value={h.HeadHash} label="chain head hash" /></td>
                    <td className="mono" style={{ fontSize: 11 }}>{new Date(h.UpdatedAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        </div>
      )}

      {/* Event log */}
      <Panel
        title="Event Log"
        action={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <select className="select" style={{ width: "auto", fontSize: 11 }} value={chainFilter} onChange={(e) => setChainFilter(e.target.value)}>
              <option value="">all chains</option>
              {heads.map((h) => (
                <option key={h.ChainName} value={h.ChainName}>{h.ChainName}</option>
              ))}
            </select>
            <select className="select" style={{ width: "auto", fontSize: 11 }} value={String(limit)} onChange={(e) => setLimit(Number(e.target.value))}>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="200">200</option>
              <option value="500">500</option>
            </select>
          </div>
        }
      >
        <div className="filter-grid">
          <input className="input" placeholder="action contains" value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setCursor(0); }} />
          <select className="select" value={resultFilter} onChange={(e) => { setResultFilter(e.target.value); setCursor(0); }}><option value="">all results</option><option value="success">success</option><option value="failure">failure</option><option value="requested">requested</option><option value="denied">denied</option></select>
          <input className="input" placeholder="actor hash" value={actorFilter} onChange={(e) => { setActorFilter(e.target.value); setCursor(0); }} />
          <input className="input" placeholder="target hash" value={targetFilter} onChange={(e) => { setTargetFilter(e.target.value); setCursor(0); }} />
          <input className="input" type="datetime-local" value={fromFilter} onChange={(e) => { setFromFilter(e.target.value); setCursor(0); }} />
          <input className="input" type="datetime-local" value={toFilter} onChange={(e) => { setToFilter(e.target.value); setCursor(0); }} />
        </div>
        {eventsError ? (
          <ErrorState message={eventsError.message} />
        ) : eventsLoading ? (
          <Loading label="loading events..." />
        ) : events.length === 0 ? (
          <EmptyState icon={<ScrollText />} message="no audit events; perform encrypt, key lifecycle, or policy operations to populate" />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 20 }}></th>
                  <th>Seq</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Chain</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Result</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => {
                  const highRisk = HIGH_RISK_ACTIONS.includes(e.Action);
                  return (
                    <tr key={i} style={{ cursor: "default" }}>
                      <td>
                        {highRisk && (
                          <AlertTriangle size={13} style={{ color: "var(--accent)" }} />
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>{e.Sequence}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{new Date(e.Timestamp).toLocaleString()}</td>
                      <td>
                        <span
                          style={{
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: 11,
                            color: highRisk ? "var(--accent)" : "var(--text-secondary)",
                            fontWeight: highRisk ? 600 : 400,
                          }}
                        >
                          {e.Action}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>{e.ChainName}</td>
                      <td><HashValue value={e.ActorHash} label="actor fingerprint" /></td>
                      <td><HashValue value={e.TargetIDHash} label="target fingerprint" /></td>
                      <td>
                        <span style={{ color: RESULT_COLOR[e.Result] ?? "var(--text-secondary)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>
                          {e.Result}
                        </span>
                      </td>
                      <td className="audit-chain-hash"><Link2 size={11} /><HashValue value={e.CurrentHash} label="audit event hash" /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="pagination-row"><button className="btn btn-ghost btn-sm" disabled={cursor === 0} onClick={() => setCursor(Math.max(0, cursor - limit))}>Previous</button><span className="mono">offset {cursor}</span><button className="btn btn-ghost btn-sm" disabled={!eventsData?.next_cursor} onClick={() => setCursor(Number(eventsData?.next_cursor))}>Next</button></div>
      </Panel>
    </PageContainer>
  );
}
