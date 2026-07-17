import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, ShieldAlert, Wrench } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths, collectOpsAction } from "../../lib/apiPaths";
import { Panel, MonoReadout, showToast } from "../index";

interface CRKEnvelopeStatus {
  id: string;
  crk_version_id: string;
  node_id: string;
  created_at: string;
  envelope_bytes: number;
  wrapped_crk_bytes: number;
  crk_version: number;
  nrwk_name: string;
  cluster_id: string;
  plane_role: string;
  crk_aad_digest: string;
  expected_aad_digest: string;
  digest_valid: boolean;
}

interface RepairResponse {
  status: string;
  envelope: CRKEnvelopeStatus;
}

export function CRKPanel() {
  const [crkVersionID, setCRKVersionID] = useState("");
  const [nodeID, setNodeID] = useState("node-bootstrap");
  const [status, setStatus] = useState<CRKEnvelopeStatus | null>(null);
  const qc = useQueryClient();

  const loadMut = useMutation({
    mutationFn: () => api.get<CRKEnvelopeStatus>(apiPaths.ops.crkEnvelope({ crk_version_id: crkVersionID || undefined, node_id: nodeID || undefined })),
    onSuccess: (r) => {
      setStatus(r);
      showToast("crk envelope loaded", "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const repairMut = useMutation({
    mutationFn: () => { const action = collectOpsAction("Repair CRK envelope AAD digest"); if (!action) throw new Error("operation cancelled"); return api.post<RepairResponse>(apiPaths.ops.repairCRK({ crk_version_id: crkVersionID || undefined, node_id: nodeID || undefined }), action.body, action.headers); },
    onSuccess: (r) => {
      setStatus(r.envelope);
      showToast(`crk envelope ${r.status}`, "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  return (
    <Panel title="CRK Envelope">
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <div>
            <label className="input-label">CRK Version ID</label>
            <input className="input" value={crkVersionID} onChange={(e) => setCRKVersionID(e.target.value)} placeholder="latest if empty" />
          </div>
          <div>
            <label className="input-label">Node ID</label>
            <input className="input" value={nodeID} onChange={(e) => setNodeID(e.target.value)} placeholder="node-bootstrap" />
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={() => loadMut.mutate()} disabled={loadMut.isPending}>
            <RefreshCw size={14} /> {loadMut.isPending ? "Loading..." : "Load Status"}
          </button>
          <button className="btn btn-secondary" onClick={() => repairMut.mutate()} disabled={repairMut.isPending}>
            <Wrench size={14} /> {repairMut.isPending ? "Repairing..." : "Repair AAD Digest"}
          </button>
        </div>

        {status && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: "var(--bg-inset)", border: "1px solid var(--border)" }}>
              <ShieldAlert size={14} style={{ color: status.digest_valid ? "var(--success)" : "var(--danger)" }} />
              <span className="mono" style={{ color: status.digest_valid ? "var(--success)" : "var(--danger)", fontSize: 12 }}>
                {status.digest_valid ? "CRK AAD digest valid" : "CRK AAD digest mismatch"}
              </span>
            </div>
            <div className="kv-grid">
              {[
                ["Envelope ID", status.id],
                ["CRK Version ID", status.crk_version_id],
                ["Node ID", status.node_id],
                ["NRWK", status.nrwk_name],
                ["Cluster", status.cluster_id],
                ["Plane Role", status.plane_role],
                ["CRK Version", String(status.crk_version)],
                ["Envelope Bytes", String(status.envelope_bytes)],
                ["Wrapped CRK Bytes", String(status.wrapped_crk_bytes)],
                ["Created", status.created_at],
              ].map(([k, v]) => (
                <div key={k} className="kv-row">
                  <span>{k}</span>
                  <strong>{v}</strong>
                </div>
              ))}
            </div>
            <MonoReadout label="Current CRK AAD Digest" value={status.crk_aad_digest || "(empty)"} copyable />
            <MonoReadout label="Expected CRK AAD Digest" value={status.expected_aad_digest || "(unavailable)"} copyable />
          </div>
        )}
      </div>
    </Panel>
  );
}
