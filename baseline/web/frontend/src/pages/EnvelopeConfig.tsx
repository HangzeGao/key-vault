import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, HttpError } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { KVList, Loading, ErrorState, PageContainer, Panel, showToast } from "../components";
import type { EnvelopeFormatDescription, EnvelopeFormatProfile, TenantEnvelopeConfig } from "../lib/types";

const DEFAULT_PROFILE: EnvelopeFormatProfile = {
  format_id: "configurable-json-v1",
  adapter: "configurable-json-v1",
  description: "default configurable JSON profile",
  field_mappings: [
    { path: "$.version", source: "core.version", required: true },
    { path: "$.flags", source: "core.flags", required: true },
    { path: "$.suite_id", source: "core.suite_id", required: true },
    { path: "$.key_id", source: "core.key_id", required: true },
    { path: "$.key_version", source: "core.key_version", required: true },
    { path: "$.policy_version", source: "core.policy_version", required: true },
    { path: "$.nonce", source: "core.nonce", required: true, encoding: "base64raw" },
    { path: "$.ciphertext", source: "core.ciphertext", required: true, encoding: "base64raw" },
    { path: "$.tag", source: "core.tag", required: true, encoding: "base64raw" },
    { path: "$.aad_hash", source: "core.aad_hash", required: false, encoding: "base64raw" },
  ],
  extensions: [],
};

export function EnvelopeConfigPage() {
  const { tenantId } = useAuth();
  const qc = useQueryClient();
  const [editMode, setEditMode] = useState(false);
  const [defaultFormat, setDefaultFormat] = useState("");
  const [allowedFormats, setAllowedFormats] = useState<string[]>([]);
  const [aadRequired, setAADRequired] = useState(false);
  const [profilesJSON, setProfilesJSON] = useState("[]");
  const [selectedProfile, setSelectedProfile] = useState(0);

  const { data: config, isLoading, error } = useQuery({
    queryKey: ["envelope-config", tenantId],
    queryFn: () => api.get<TenantEnvelopeConfig>(apiPaths.tenantEnvelopeConfig(tenantId)),
    enabled: !!tenantId,
    retry: (failureCount, err) => {
      if (err instanceof HttpError && err.status === 404) return false;
      return failureCount < 1;
    },
  });

  const isNotFound = error instanceof HttpError && error.status === 404;

  const { data: formatsData, error: formatsError } = useQuery({
    queryKey: ["envelope-formats"],
    queryFn: () => api.get<{ formats: EnvelopeFormatDescription[] }>(apiPaths.envelopeFormats),
  });
  const formats = formatsData?.formats ?? [];

  const profiles = useMemo(() => config?.profiles ?? [], [config?.profiles]);
  const profileIds = profiles.map((p) => p.format_id);
  const visibleFormats = [...formats.map((f) => f.format_id), ...profileIds.filter((id) => !formats.some((f) => f.format_id === id))];

  const editProfiles = useMemo<EnvelopeFormatProfile[]>(() => {
    try { const value = JSON.parse(profilesJSON); return Array.isArray(value) ? value : []; } catch { return []; }
  }, [profilesJSON]);
  const setEditProfiles = (next: EnvelopeFormatProfile[]) => setProfilesJSON(JSON.stringify(next, null, 2));
  const profileErrors = useMemo(() => {
    const errors: string[] = []; const ids = new Set<string>(); const adapters = new Set(formats.map((f) => f.format_id));
    editProfiles.forEach((profile, index) => {
      if (!profile.format_id.trim()) errors.push(`profile ${index + 1}: format_id is required`);
      if (ids.has(profile.format_id)) errors.push(`duplicate format_id: ${profile.format_id}`); ids.add(profile.format_id);
      if (!adapters.has(profile.adapter)) errors.push(`${profile.format_id || `profile ${index + 1}`}: adapter is not registered`);
      profile.field_mappings?.forEach((mapping, row) => { if (!mapping.path.startsWith("$.")) errors.push(`${profile.format_id} mapping ${row + 1}: path must start with $.`); if (!mapping.source) errors.push(`${profile.format_id} mapping ${row + 1}: source is required`); });
    }); return errors;
  }, [editProfiles, formats]);
  const profileDiff = useMemo(() => {
    const before = new Map((config?.profiles ?? []).map((p) => [p.format_id, JSON.stringify(p)]));
    const after = new Map(editProfiles.map((p) => [p.format_id, JSON.stringify(p)]));
    return { added: [...after.keys()].filter((id) => !before.has(id)), removed: [...before.keys()].filter((id) => !after.has(id)), changed: [...after.keys()].filter((id) => before.has(id) && before.get(id) !== after.get(id)) };
  }, [config?.profiles, editProfiles]);

  const updateMut = useMutation({
    mutationFn: (req: { default_format: string; allowed_formats: string[]; profiles: EnvelopeFormatProfile[]; aad_required: boolean; version: number }) =>
      api.put<TenantEnvelopeConfig>(apiPaths.tenantEnvelopeConfig(tenantId), req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["envelope-config", tenantId] });
      setEditMode(false);
      showToast("envelope config saved", "success");
    },
    onError: (e: Error) => { if (e instanceof HttpError && e.status === 409) { qc.invalidateQueries({ queryKey: ["envelope-config", tenantId] }); showToast("version conflict: latest config reloaded; your edits were preserved", "error"); return; } showToast(e.message, "error"); },
  });

  if (isLoading) return <PageContainer><Loading label="loading envelope config..." /></PageContainer>;
  if (error && !isNotFound) return <PageContainer><ErrorState message={error.message} /></PageContainer>;
  if (formatsError) return <PageContainer><ErrorState message={formatsError.message} /></PageContainer>;

  const startEdit = () => {
    const firstFormat = formats[0]?.format_id ?? "kvlt-binary-v1";
    setDefaultFormat(config?.default_format ?? firstFormat);
    setAllowedFormats(config?.allowed_formats ?? formats.map((f) => f.format_id));
    setAADRequired(config?.aad_required ?? false);
    setProfilesJSON(JSON.stringify(config?.profiles ?? [], null, 2));
    setSelectedProfile(0);
    setEditMode(true);
  };

  const addDefaultProfile = () => {
    let next: EnvelopeFormatProfile[];
    try {
      next = JSON.parse(profilesJSON || "[]");
      if (!Array.isArray(next)) throw new Error("profiles must be an array");
    } catch (e) {
      showToast(e instanceof Error ? e.message : "invalid profiles JSON", "error");
      return;
    }
    if (next.some((p) => p.format_id === DEFAULT_PROFILE.format_id)) {
      showToast("configurable-json-v1 profile already exists", "error");
      return;
    }
    setProfilesJSON(JSON.stringify([...next, DEFAULT_PROFILE], null, 2));
    if (!allowedFormats.includes(DEFAULT_PROFILE.format_id)) {
      setAllowedFormats([...allowedFormats, DEFAULT_PROFILE.format_id]);
    }
  };

  const toggleAllowed = (formatID: string) => {
    if (allowedFormats.includes(formatID)) {
      setAllowedFormats(allowedFormats.filter((f) => f !== formatID));
      return;
    }
    setAllowedFormats([...allowedFormats, formatID]);
  };

  const save = () => {
    let nextProfiles: EnvelopeFormatProfile[];
    try {
      nextProfiles = JSON.parse(profilesJSON || "[]");
      if (!Array.isArray(nextProfiles)) throw new Error("profiles must be an array");
    } catch (e) {
      showToast(e instanceof Error ? e.message : "invalid profiles JSON", "error");
      return;
    }
    if (!defaultFormat || !allowedFormats.includes(defaultFormat)) {
      showToast("default format must be in allowed formats", "error");
      return;
    }
    if (profileErrors.length) { showToast(profileErrors[0], "error"); return; }
    updateMut.mutate({
      default_format: defaultFormat,
      allowed_formats: allowedFormats,
      profiles: nextProfiles,
      aad_required: aadRequired,
      version: config?.version ?? 0,
    });
  };

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Envelope Config</h1>
          <p className="section-subtitle">Tenant envelope profiles and allowed serialization formats for {tenantId}</p>
        </div>
      </div>

      <div className="grid-2 page-section">
        <Panel
          title="Current Configuration"
          action={
            !editMode ? (
              <button className="btn btn-primary btn-sm" onClick={startEdit}>{config ? "Edit" : "Create"}</button>
            ) : (
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => setEditMode(false)}>Cancel</button>
                <button className="btn btn-primary btn-sm" onClick={save} disabled={updateMut.isPending}>Save</button>
              </div>
            )
          }
        >
          {config ? (
            <KVList
              items={[
                ["Tenant", config.tenant_id],
                ["Default Format", <span className="mono" style={{ color: "var(--accent)" }}>{config.default_format}</span>],
                ["Allowed Formats", config.allowed_formats.join(", ")],
                ["Profiles", `${profiles.length}`],
                ["AAD Policy", config.aad_required ? "required" : "optional"],
                ["Version", `v${config.version}`],
                ["Updated By", <span className="mono" style={{ fontSize: 11 }}>{config.updated_by}</span>],
                ["Updated At", new Date(config.updated_at).toLocaleString()],
              ]}
            />
          ) : (
            <div className="empty-copy">
              No envelope config found.
            </div>
          )}
        </Panel>

        <Panel title="Formats">
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {visibleFormats.map((formatID) => {
              const desc = formats.find((f) => f.format_id === formatID);
              const isAllowed = editMode ? allowedFormats.includes(formatID) : config?.allowed_formats.includes(formatID);
              const isDefault = editMode ? defaultFormat === formatID : config?.default_format === formatID;
              return (
                <div key={formatID} style={{ padding: "12px 14px", background: "var(--bg-inset)", border: `1px solid ${isDefault ? "var(--accent)" : "var(--border)"}`, borderRadius: 2 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                    <span className="mono" style={{ color: isDefault ? "var(--accent)" : "var(--text-primary)", fontSize: 12 }}>{formatID}</span>
                    <span className="mono" style={{ color: "var(--text-tertiary)", fontSize: 10 }}>{isDefault ? "default" : isAllowed ? "allowed" : "disabled"}</span>
                  </div>
                  {desc && <div style={{ color: "var(--text-secondary)", fontSize: 11, marginTop: 6 }}>{desc.description}</div>}
                  {editMode && (
                    <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                      <button className="btn btn-ghost btn-sm" onClick={() => toggleAllowed(formatID)}>{isAllowed ? "Disable" : "Allow"}</button>
                      {isAllowed && <button className="btn btn-ghost btn-sm" onClick={() => setDefaultFormat(formatID)}>Set Default</button>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      {editMode ? (
        <Panel title="Profile Editor" action={<button className="btn btn-ghost btn-sm" onClick={addDefaultProfile}>Add Configurable JSON</button>}>
          <div className="profile-editor">
            <div className="profile-list">{editProfiles.map((profile, index) => <button key={`${profile.format_id}-${index}`} className={`profile-list-item ${selectedProfile === index ? "active" : ""}`} onClick={() => setSelectedProfile(index)}>{profile.format_id || `Profile ${index + 1}`}</button>)}</div>
            {editProfiles[selectedProfile] && (() => { const profile = editProfiles[selectedProfile]; const updateProfile = (patch: Partial<EnvelopeFormatProfile>) => setEditProfiles(editProfiles.map((item, index) => index === selectedProfile ? { ...item, ...patch } : item)); return <div className="profile-form">
              <div className="form-grid"><label><span className="input-label">Format ID</span><input className="input" value={profile.format_id} onChange={(e) => updateProfile({ format_id: e.target.value })} /></label><label><span className="input-label">Adapter</span><select className="select" value={profile.adapter} onChange={(e) => updateProfile({ adapter: e.target.value })}>{formats.map((format) => <option key={format.format_id} value={format.format_id}>{format.format_id}</option>)}</select></label></div>
              <label><span className="input-label">Description</span><input className="input" value={profile.description ?? ""} onChange={(e) => updateProfile({ description: e.target.value })} /></label>
              <div className="mapping-header"><span className="input-label">Field mappings</span><button className="btn btn-ghost btn-sm" onClick={() => updateProfile({ field_mappings: [...(profile.field_mappings ?? []), { path: "$.", source: "core.", required: false }] })}>Add row</button></div>
              <div className="mapping-table">{(profile.field_mappings ?? []).map((mapping, row) => { const updateMapping = (patch: Partial<typeof mapping>) => updateProfile({ field_mappings: profile.field_mappings!.map((item, index) => index === row ? { ...item, ...patch } : item) }); return <div className="mapping-row" key={row}><input className="input" value={mapping.path} onChange={(e) => updateMapping({ path: e.target.value })} placeholder="$.field" /><input className="input" value={mapping.source} onChange={(e) => updateMapping({ source: e.target.value })} placeholder="core.field" /><select className="select" value={mapping.encoding ?? ""} onChange={(e) => updateMapping({ encoding: e.target.value || undefined })}><option value="">raw</option><option value="base64">base64</option><option value="base64raw">base64raw</option><option value="hex">hex</option></select><label className="check-label"><input type="checkbox" checked={mapping.required} onChange={(e) => updateMapping({ required: e.target.checked })} /> required</label><button className="btn btn-ghost btn-sm" onClick={() => updateProfile({ field_mappings: profile.field_mappings!.filter((_, index) => index !== row) })}>Remove</button></div>; })}</div>
              <button className="btn btn-secondary btn-sm" onClick={() => { setEditProfiles(editProfiles.filter((_, index) => index !== selectedProfile)); setSelectedProfile(Math.max(0, selectedProfile - 1)); }}>Delete profile</button>
            </div>; })()}
          </div>
          <label className="check-label"><input type="checkbox" checked={aadRequired} onChange={(e) => setAADRequired(e.target.checked)} /> Require non-empty caller aad_b64 for encrypt/decrypt and batch APIs</label>
          {profileErrors.length > 0 && <div className="validation-errors">{profileErrors.map((message) => <div key={message}>{message}</div>)}</div>}
          <div className="diff-preview"><strong>Pending diff</strong><span>Added: {profileDiff.added.join(", ") || "none"}</span><span>Changed: {profileDiff.changed.join(", ") || "none"}</span><span>Removed: {profileDiff.removed.join(", ") || "none"}</span></div>
          <details><summary className="mono">Advanced JSON / schema preview</summary>
          <textarea
            className="textarea mono"
            value={profilesJSON}
            onChange={(e) => setProfilesJSON(e.target.value)}
            style={{ minHeight: 360 }}
          />
          </details>
        </Panel>
      ) : (
        <Panel title="Profiles">
          <pre className="mono" style={{ whiteSpace: "pre-wrap", margin: 0, color: "var(--text-secondary)", fontSize: 11 }}>
            {JSON.stringify(profiles, null, 2)}
          </pre>
        </Panel>
      )}
    </PageContainer>
  );
}
