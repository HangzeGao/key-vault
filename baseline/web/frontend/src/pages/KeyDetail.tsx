import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Ban, CalendarClock, CheckCircle, Trash2, AlertTriangle, Pencil, RotateCcw, Archive } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { PageContainer, Panel, StatusPill, SuiteBadge, Loading, ErrorState, Modal, KVList, showToast } from "../components";
import type { KeyDTO } from "../lib/types";

const DESTROY_GRACE_HOURS = 24;

export function KeyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [confirmDestroy, setConfirmDestroy] = useState(false);
  const [confirmArchive, setConfirmArchive] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [showExtend, setShowExtend] = useState(false);

  const { data: key, isLoading, error } = useQuery({
    queryKey: ["key", id],
    queryFn: () => api.get<KeyDTO>(apiPaths.key(id!)),
    enabled: !!id,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["key", id] });
    qc.invalidateQueries({ queryKey: ["keys"] });
  };

  const disableMut = useMutation({
    mutationFn: () => api.post(apiPaths.keyAction(id!, "disable")),
    onSuccess: () => { invalidate(); showToast("key disabled", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });
  const enableMut = useMutation({
    mutationFn: () => api.post(apiPaths.keyAction(id!, "enable")),
    onSuccess: () => { invalidate(); showToast("key enabled", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });
  const updateMut = useMutation({
    mutationFn: (req: { name: string; tags?: Record<string, string>; expires_at?: string }) => api.patch<KeyDTO>(apiPaths.key(id!), req),
    onSuccess: () => {
      invalidate();
      qc.invalidateQueries({ queryKey: ["keys"] });
      setShowEdit(false);
      setShowExtend(false);
      showToast("key metadata updated", "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });
  const destroyMut = useMutation({
    mutationFn: () => api.delete(apiPaths.key(id!)),
    onSuccess: () => { invalidate(); setConfirmDestroy(false); showToast("destroy scheduled", "warning"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });
  const cancelDestroyMut = useMutation({
    mutationFn: () => api.post(apiPaths.keyAction(id!, "cancel-destroy")),
    onSuccess: () => { invalidate(); showToast("destroy cancelled", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });
  const archiveMut = useMutation({
    mutationFn: () => api.post<KeyDTO>(apiPaths.keyAction(id!, "archive")),
    onSuccess: () => { invalidate(); setConfirmArchive(false); showToast("destroyed key archived", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  if (isLoading) return <PageContainer><Loading label="loading key..." /></PageContainer>;
  if (error) return <PageContainer><ErrorState message={error.message} /></PageContainer>;
  if (!key) return <PageContainer><ErrorState message="key not found" /></PageContainer>;

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <button className="btn btn-ghost btn-sm" onClick={() => navigate("/ui/keys")} style={{ marginBottom: 10 }}>
            <ArrowLeft size={14} /> Keys
          </button>
          <h1 className="section-title">{key.name}</h1>
          <p className="section-subtitle">Key metadata, state transitions, and lifecycle operations</p>
        </div>
        <div className="page-header-actions">
          <StatusPill status={key.status} />
          <SuiteBadge suite={key.suite_id} />
          <span className="mono" style={{ color: "var(--text-tertiary)", fontSize: 12 }}>v{key.current_version}</span>
          <button className="btn btn-secondary btn-sm" onClick={() => setShowEdit(true)}>
            <Pencil size={14} /> Edit
          </button>
        </div>
      </div>

      <div className="grid-2 page-section">
        <Panel title="Metadata">
          <KVList
            items={[
              ["Key ID", key.key_id],
              ["Tenant", key.tenant_id],
              ["Purpose", key.purpose],
              ["Policy", key.policy_id],
              ["Suite", key.suite_id],
              ["Version", `v${key.current_version}`],
              ["Status", key.status],
              ["Expires", key.expires_at ? new Date(key.expires_at).toLocaleString() : "never"],
              ["Archived", key.archived_at ? new Date(key.archived_at).toLocaleString() : "-"],
              ["Created", new Date(key.created_at).toLocaleString()],
            ]}
          />
        </Panel>

        <Panel title="State Machine Operations">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <p style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
              Available actions depend on the current key state.
            </p>
            {key.status === "ACTIVE" && (
              <>
                <button className="btn btn-secondary" onClick={() => disableMut.mutate()} disabled={disableMut.isPending}>
                  <Ban size={14} /> Disable
                </button>
                <button className="btn btn-danger" onClick={() => setConfirmDestroy(true)}>
                  <Trash2 size={14} /> Schedule Destroy
                </button>
              </>
            )}
            {key.status === "DISABLED" && (
              <button className="btn btn-primary" onClick={() => enableMut.mutate()} disabled={enableMut.isPending}>
                <CheckCircle size={14} /> Enable
              </button>
            )}
            {key.status === "DESTROY_PENDING" && (
              <>
                <div style={{ display: "flex", gap: 8, alignItems: "center", color: "var(--warning)", fontSize: 12, fontFamily: '"JetBrains Mono", monospace' }}>
                  <AlertTriangle size={14} />
                  destroy pending: final destruction after {DESTROY_GRACE_HOURS} hours; decryption only, no new encryption
                </div>
                <button className="btn btn-secondary" onClick={() => cancelDestroyMut.mutate()} disabled={cancelDestroyMut.isPending}>
                  <RotateCcw size={14} /> Cancel Destroy
                </button>
              </>
            )}
            {key.status === "EXPIRED" && (
              <>
                <div style={{ display: "flex", gap: 8, alignItems: "center", color: "var(--warning)", fontSize: 12, fontFamily: '"JetBrains Mono", monospace' }}>
                  <AlertTriangle size={14} />
                  expired: extend expires_at to restore active use
                </div>
                <button className="btn btn-primary" onClick={() => setShowExtend(true)}>
                  <CalendarClock size={14} /> Extend Expiration
                </button>
              </>
            )}
            {key.status === "DESTROYED" && (
              <>
                <div style={{ display: "flex", gap: 8, alignItems: "center", color: "var(--danger)", fontSize: 12, fontFamily: '"JetBrains Mono", monospace' }}>
                  <AlertTriangle size={14} />
                  key destroyed: permanently inaccessible
                </div>
                {!key.archived_at && (
                  <button className="btn btn-secondary" onClick={() => setConfirmArchive(true)}>
                    <Archive size={14} /> Archive Tombstone
                  </button>
                )}
                {key.archived_at && (
                  <div style={{ fontSize: 12, color: "var(--text-tertiary)", fontFamily: '"JetBrains Mono", monospace' }}>
                    archived tombstone: hidden from default inventory
                  </div>
                )}
              </>
            )}
          </div>
        </Panel>
      </div>

      {showEdit && (
        <EditKeyModal
          keyDTO={key}
          loading={updateMut.isPending}
          onClose={() => setShowEdit(false)}
          onSave={(req) => updateMut.mutate(req)}
        />
      )}

      {showExtend && (
        <ExtendExpirationModal
          keyDTO={key}
          loading={updateMut.isPending}
          onClose={() => setShowExtend(false)}
          onSave={(expiresAt) => updateMut.mutate({
            name: key.name,
            tags: key.tags ?? {},
            expires_at: expiresAt,
          })}
        />
      )}

      {confirmDestroy && (
        <Modal
          title="Confirm Destroy"
          danger
          onClose={() => setConfirmDestroy(false)}
          onConfirm={() => destroyMut.mutate()}
          confirmLabel="Schedule Destroy"
        >
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            This will schedule <strong style={{ color: "var(--text-primary)" }}>{key.name}</strong> for destruction.
            After the {DESTROY_GRACE_HOURS}-hour grace period, the key material will be permanently erased.
            Decryption remains possible until final destruction.
          </p>
        </Modal>
      )}

      {confirmArchive && (
        <Modal
          title="Archive Destroyed Key"
          onClose={() => setConfirmArchive(false)}
          onConfirm={() => archiveMut.mutate()}
          confirmLabel="Archive Tombstone"
        >
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            This hides <strong style={{ color: "var(--text-primary)" }}>{key.name}</strong> from the default key inventory.
            The tombstone, key ID history, and audit evidence remain available when archived keys are shown.
          </p>
        </Modal>
      )}
    </PageContainer>
  );
}

function defaultExtendLocalValue() {
  const d = new Date();
  d.setDate(d.getDate() + 30);
  d.setSeconds(0, 0);
  return localDateTimeValue(d);
}

function localDateTimeValue(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function ExtendExpirationModal({
  keyDTO,
  loading,
  onClose,
  onSave,
}: {
  keyDTO: KeyDTO;
  loading: boolean;
  onClose: () => void;
  onSave: (expiresAt: string) => void;
}) {
  const [expiresAt, setExpiresAt] = useState(defaultExtendLocalValue());

  const save = () => {
    if (!expiresAt) {
      showToast("expires_at is required", "error");
      return;
    }
    const next = new Date(expiresAt);
    if (!Number.isFinite(next.getTime()) || next <= new Date()) {
      showToast("expires_at must be in the future", "error");
      return;
    }
    onSave(next.toISOString());
  };

  return (
    <Modal title="Extend Expiration" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
          Extend <span className="mono" style={{ color: "var(--text-primary)" }}>{keyDTO.key_id}</span> by setting a future expiration time.
        </div>
        <div>
          <label className="input-label">New Expires At</label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} autoFocus />
        </div>
      </div>
      <div style={{ marginTop: 20, display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <button className="btn btn-secondary btn-sm" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary btn-sm" disabled={loading} onClick={save}>
          {loading ? "Extending..." : "Extend"}
        </button>
      </div>
    </Modal>
  );
}

function EditKeyModal({
  keyDTO,
  loading,
  onClose,
  onSave,
}: {
  keyDTO: KeyDTO;
  loading: boolean;
  onClose: () => void;
  onSave: (req: { name: string; tags?: Record<string, string>; expires_at?: string }) => void;
}) {
  const [name, setName] = useState(keyDTO.name);
  const [tagsText, setTagsText] = useState(JSON.stringify(keyDTO.tags ?? {}, null, 2));
  const [expiresAt, setExpiresAt] = useState(keyDTO.expires_at ? keyDTO.expires_at.slice(0, 16) : "");

  const save = () => {
    let tags: Record<string, string> | undefined;
    try {
      tags = JSON.parse(tagsText || "{}") as Record<string, string>;
    } catch {
      showToast("tags must be a JSON object", "error");
      return;
    }
    onSave({ name: name.trim(), tags, expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined });
  };

  return (
    <Modal title="Edit Key Metadata" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <label className="input-label">Name</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div>
          <label className="input-label">Expires At</label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </div>
        <div>
          <label className="input-label">Tags JSON</label>
          <textarea
            className="input"
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            rows={6}
            style={{ fontFamily: '"JetBrains Mono", monospace', resize: "vertical" }}
          />
        </div>
      </div>
      <div style={{ marginTop: 20, display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <button className="btn btn-secondary btn-sm" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary btn-sm" disabled={!name.trim() || loading} onClick={save}>
          {loading ? "Saving..." : "Save"}
        </button>
      </div>
    </Modal>
  );
}
