import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Plus, KeyRound, Upload, UploadCloud, Archive } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { PageContainer, Panel, StatusPill, SuiteBadge, Loading, showToast } from "../components";
import { CreateKeyModal } from "../components/keys/CreateKeyModal";
import { ImportKeyModal } from "../components/keys/ImportKeyModal";
import { BatchImportKeyModal } from "../components/keys/BatchImportKeyModal";
import type { BatchImportKeyResult, KeyDTO, CreateKeyReq, ImportKeyReq, SignedPolicy } from "../lib/types";

export function KeysPage() {
  const { tenantId } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [showBatchImport, setShowBatchImport] = useState(false);
  const [showArchived, setShowArchived] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ["keys", tenantId, showArchived],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keysList({ include_archived: showArchived || undefined })),
  });
  const { data: policy } = useQuery({ queryKey: ["signed-policy"], queryFn: () => api.get<SignedPolicy>(apiPaths.policy.signed) });

  const createMut = useMutation({
    mutationFn: (vars: { req: CreateKeyReq; idempotencyKey?: string }) =>
      api.post<KeyDTO>(apiPaths.keys, vars.req,
        vars.idempotencyKey ? { "Idempotency-Key": vars.idempotencyKey } : undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      setShowCreate(false);
      showToast("key created", "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const importMut = useMutation({
    mutationFn: (vars: { req: ImportKeyReq; idempotencyKey?: string }) =>
      api.post<KeyDTO>(apiPaths.importKey, vars.req,
        vars.idempotencyKey ? { "Idempotency-Key": vars.idempotencyKey } : undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      setShowImport(false);
      showToast("key imported", "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const batchImportMut = useMutation({
    mutationFn: (entries: ImportKeyReq[]) => api.post<{ results: BatchImportKeyResult[] }>(apiPaths.importKeysBatch, { tenant_id: tenantId, entries }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keys"] }),
  });

  const keys = data?.keys ?? [];

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Keys</h1>
          <p className="section-subtitle">Cryptographic key inventory and lifecycle state for tenant {tenantId}</p>
        </div>
      </div>

      <Panel
        title="Key Inventory"
        action={
          <div style={{ display: "flex", gap: 8 }}>
            <button className={showArchived ? "btn btn-secondary btn-sm" : "btn btn-ghost btn-sm"} onClick={() => setShowArchived((value) => !value)}>
              <Archive size={14} /> {showArchived ? "Hide Archived" : "Show Archived"}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowBatchImport(true)}>
              <UploadCloud size={14} /> Batch Import
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowImport(true)}>
              <Upload size={14} /> Import Key
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
              <Plus size={14} /> Create Key
            </button>
          </div>
        }
      >
        {isLoading ? (
          <Loading label="loading keys..." />
        ) : error ? (
          <div style={{ color: "var(--danger)", fontFamily: '"JetBrains Mono", monospace', fontSize: 12 }}>
            {error.message}
          </div>
        ) : keys.length === 0 ? (
          <div style={{ textAlign: "center", padding: 40, color: "var(--text-tertiary)" }}>
            <KeyRound size={28} style={{ opacity: 0.3, marginBottom: 10 }} />
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12 }}>No keys yet. Create or import one to begin.</div>
          </div>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key ID</th>
                  <th>Suite</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Purpose</th>
                  <th>Expires</th>
                  <th>Created</th>
                  {showArchived && <th>Archived</th>}
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.key_id} onClick={() => navigate(`/ui/keys/${k.key_id}`)}>
                    <td style={{ fontWeight: 500 }}>{k.name}</td>
                    <td className="mono">{k.key_id.slice(0, 20)}...</td>
                    <td><SuiteBadge suite={k.suite_id} /></td>
                    <td className="mono">v{k.current_version}</td>
                    <td><StatusPill status={k.status} /></td>
                    <td className="mono" style={{ fontSize: 12 }}>{k.purpose}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{k.expires_at ? new Date(k.expires_at).toLocaleString() : "never"}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{new Date(k.created_at).toLocaleString()}</td>
                    {showArchived && <td className="mono" style={{ fontSize: 11 }}>{k.archived_at ? new Date(k.archived_at).toLocaleString() : "-"}</td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {showCreate && (
        <CreateKeyModal
          onClose={() => setShowCreate(false)}
          onCreate={(req, idempotencyKey) => createMut.mutate({ req, idempotencyKey })}
          loading={createMut.isPending}
          policyID={policy?.policy_id}
        />
      )}

      {showImport && (
        <ImportKeyModal
          onClose={() => setShowImport(false)}
          onImport={(req, idempotencyKey) => importMut.mutate({ req, idempotencyKey })}
          loading={importMut.isPending}
          policyID={policy?.policy_id}
        />
      )}
      {showBatchImport && <BatchImportKeyModal onClose={() => setShowBatchImport(false)} onImport={(entries) => batchImportMut.mutateAsync(entries)} policyID={policy?.policy_id} />}
    </PageContainer>
  );
}
