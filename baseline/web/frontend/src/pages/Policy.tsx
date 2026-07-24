import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Shield, RefreshCw, KeyRound, FileSignature, CheckCircle } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { PageContainer, Panel, Loading, ErrorState, showToast } from "../components";
import type { SignedPolicy } from "../lib/types";

const SUITE_STATUS_COLOR: Record<string, string> = {
  active: "var(--success)",
  decrypt_only: "var(--warning)",
  disabled: "var(--danger)",
};

export function PolicyPage() {
  const qc = useQueryClient();

  const { data: signed, isLoading, error } = useQuery({
    queryKey: ["signed-policy"],
    queryFn: () => api.get<SignedPolicy>(apiPaths.policy.signed),
  });

  const reloadMut = useMutation({
    mutationFn: () => api.post<{ status: string }>(apiPaths.policy.reload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["signed-policy"] });
      showToast("policy reloaded (signature re-verified)", "success");
    },
    onError: (e: Error) => showToast(`reload failed: ${e.message}`, "error"),
  });

  if (isLoading) return <PageContainer><Loading label="loading signed policy..." /></PageContainer>;
  if (error) return <PageContainer><ErrorState message={error.message} /></PageContainer>;
  if (!signed) return <PageContainer><ErrorState message="no signed policy loaded" /></PageContainer>;

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Policy</h1>
          <p className="section-subtitle">Signed policy package, Ed25519 verification, and hot reload controls</p>
        </div>
        <div className="page-header-actions">
          <button
            className="btn btn-primary btn-sm"
            disabled={reloadMut.isPending}
            onClick={() => reloadMut.mutate()}
          >
            <RefreshCw size={12} /> {reloadMut.isPending ? "Reloading..." : "Hot Reload"}
          </button>
        </div>
      </div>

      {/* Policy metadata + signature */}
      <div className="grid-2 page-section">
        <Panel title="Policy Package">
          <dl className="kv-list">
            <dt>Policy ID</dt>
            <dd className="mono" style={{ fontWeight: 600 }}>{signed.policy_id}</dd>
            <dt>Version</dt>
            <dd className="mono">v{signed.version}</dd>
            <dt>Status</dt>
            <dd>
              <span style={{ color: "var(--success)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>
                {signed.status}
              </span>
            </dd>
            <dt>Default Suite</dt>
            <dd className="mono">{signed.default_suite}</dd>
            <dt>Effective At</dt>
            <dd className="mono" style={{ fontSize: 11 }}>{new Date(signed.effective_at).toLocaleString()}</dd>
          </dl>
        </Panel>

        <Panel title="Signature (Ed25519)">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <FileSignature size={16} style={{ color: "var(--accent)" }} />
              <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{signed.signature.alg}</span>
              <CheckCircle size={14} style={{ color: "var(--success)" }} />
              <span style={{ color: "var(--success)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}>verified</span>
            </div>
            <dl className="kv-list">
              <dt>Key ID</dt>
              <dd className="mono" style={{ fontSize: 11 }}>
                <KeyRound size={11} style={{ display: "inline", marginRight: 4 }} />
                {signed.signature.key_id}
              </dd>
              <dt>Payload Hash</dt>
              <dd className="mono" style={{ fontSize: 11, color: "var(--accent)", wordBreak: "break-all" }}>
                {signed.signature.payload_hash}
              </dd>
              <dt>Signature</dt>
              <dd className="mono" style={{ fontSize: 11, color: "var(--text-secondary)", wordBreak: "break-all" }}>
                {signed.signature.sig.slice(0, 64)}...
              </dd>
            </dl>
          </div>
        </Panel>
      </div>

      {/* Suite matrix */}
      <Panel title="Suite Matrix (from signed policy)">
        <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Suite ID</th>
              <th>Algorithm</th>
              <th>Key Bits</th>
              <th>Mode</th>
              <th>Nonce</th>
              <th>Status</th>
              <th>Encrypt</th>
              <th>Decrypt</th>
              <th>Compliance</th>
            </tr>
          </thead>
          <tbody>
            {signed.suites.map((s) => (
              <tr key={s.suite_id}>
                <td className="mono" style={{ fontWeight: 500 }}>{s.suite_id}</td>
                <td className="mono">{s.algorithm}</td>
                <td className="mono">{s.key_bits}</td>
                <td><span className="suite-badge">{s.mode}</span></td>
                <td className="mono" style={{ fontSize: 11 }}>{s.nonce || "-"}</td>
                <td>
                  <span style={{ color: SUITE_STATUS_COLOR[s.status] ?? "var(--text-tertiary)", fontFamily: '"JetBrains Mono", monospace', fontSize: 11, textTransform: "uppercase" }}>
                    {s.status}
                  </span>
                </td>
                <td className="mono" style={{ color: s.status === "active" ? "var(--success)" : "var(--text-tertiary)" }}>
                  {s.status === "active" ? "yes" : "no"}
                </td>
                <td className="mono" style={{ color: s.status === "disabled" ? "var(--text-tertiary)" : "var(--success)" }}>
                  {s.status === "disabled" ? "no" : "yes"}
                </td>
                <td className="mono" style={{ fontSize: 11 }}>
                  {s.compliance && s.compliance.length > 0 ? s.compliance.join(", ") : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </Panel>

      {/* Cryptoperiod */}
      <div style={{ marginTop: 16 }}>
        <Panel title="Cryptoperiod Configuration">
          <div className="config-strip">
            <div className="config-item">
              <div className="input-label">Default Lifetime</div>
              <div className="mono" style={{ fontSize: 12 }}>{signed.cryptoperiod.default_days} days</div>
            </div>
            <div className="config-item">
              <div className="input-label">Max Lifetime</div>
              <div className="mono" style={{ fontSize: 12 }}>{signed.cryptoperiod.max_days} days</div>
            </div>
            <div className="config-item">
              <div className="input-label">Update Notice</div>
              <div className="mono" style={{ fontSize: 12 }}>{signed.cryptoperiod.update_notice_days} days</div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Load order */}
      <div style={{ marginTop: 16 }}>
        <Panel title="Policy Load Order (5-step verification)">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              ["1", "Format validation", "policy_id, default_suite, suites, signature fields present"],
              ["2", "Signing key status", "key_id registered and active"],
              ["3", "Signature verification", "Ed25519 verify(pubkey, canonical_payload, sig)"],
              ["4", "Semantic validation", "suites well-formed, load into temp engine"],
              ["5", "Atomic cache switch", "replace engine state only after all checks pass"],
            ].map(([step, title, desc]) => (
              <div
                key={step}
                style={{
                  display: "flex",
                  gap: 12,
                  alignItems: "flex-start",
                  padding: "10px 14px",
                  background: "var(--bg-inset)",
                  border: "1px solid var(--border)",
                  borderRadius: 2,
                }}
              >
                <Shield size={14} style={{ color: "var(--accent)", marginTop: 1, flexShrink: 0 }} />
                <div>
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>
                    Step {step} / {title}
                  </div>
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: "var(--text-tertiary)", marginTop: 2 }}>
                    {desc}
                  </div>
                </div>
                <CheckCircle size={12} style={{ color: "var(--success)", marginLeft: "auto", flexShrink: 0 }} />
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </PageContainer>
  );
}
