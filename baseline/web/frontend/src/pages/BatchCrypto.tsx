import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Lock, Unlock, Plus, Trash2, Play, CheckCircle, XCircle, Upload, Copy, RotateCcw } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { PageContainer, Panel, SuiteBadge, showToast, MonoReadout, ErrorState } from "../components";
import { fromBase64, toBase64 } from "../lib/envelope";
import type { KeyDTO, BatchResult } from "../lib/types";

interface BatchEntry {
  keyId: string;
  plaintext: string;
  aad: string;
  aadMode: AADMode;
}

interface BatchDecryptEntry {
  envelope: string;
  aad: string;
  aadMode: AADMode;
}

type AADMode = "utf8" | "base64" | "hex";

function encodeAAD(value: string, mode: AADMode): string | undefined {
  if (!value) return undefined;
  if (mode === "utf8") return toBase64(value);
  if (mode === "base64") { atob(value); return value; }
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(value)) throw new Error("hex AAD must contain complete bytes");
  const bytes = value.match(/../g)!.map((part) => String.fromCharCode(parseInt(part, 16)));
  return btoa(bytes.join(""));
}

const SAMPLE_ENTRIES: BatchEntry[] = [
  { keyId: "", plaintext: "record-001:alice", aad: "{\"object\":\"rec-001\"}", aadMode: "utf8" },
  { keyId: "", plaintext: "record-002:bob", aad: "{\"object\":\"rec-002\"}", aadMode: "utf8" },
  { keyId: "", plaintext: "record-003:carol", aad: "{\"object\":\"rec-003\"}", aadMode: "utf8" },
];

export function BatchCryptoPage() {
  const { tenantId } = useAuth();
  const [entries, setEntries] = useState<BatchEntry[]>(SAMPLE_ENTRIES.map((e) => ({ ...e })));
  const [globalKeyId, setGlobalKeyId] = useState("");
  const [results, setResults] = useState<BatchResult[] | null>(null);
  const [decEntries, setDecEntries] = useState<BatchDecryptEntry[]>([]);
  const [decResults, setDecResults] = useState<BatchResult[] | null>(null);
  const [failedOnly, setFailedOnly] = useState(false);

  const { data: keysData, error: keysError } = useQuery({
    queryKey: ["keys", tenantId],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keys),
  });
  const keys = (keysData?.keys ?? []).filter((k) => k.status === "ACTIVE");

  const updateEntry = (i: number, patch: Partial<BatchEntry>) => {
    setEntries((prev) => prev.map((e, idx) => (idx === i ? { ...e, ...patch } : e)));
  };
  const addEntry = () => setEntries((prev) => [...prev, { keyId: "", plaintext: "", aad: "", aadMode: "utf8" }]);
  const removeEntry = (i: number) => setEntries((prev) => prev.filter((_, idx) => idx !== i));
  const updateDecEntry = (i: number, patch: Partial<BatchDecryptEntry>) => {
    setDecEntries((prev) => prev.map((e, idx) => (idx === i ? { ...e, ...patch } : e)));
  };
  const addDecEntry = () => setDecEntries((prev) => [...prev, { envelope: "", aad: "", aadMode: "utf8" }]);
  const removeDecEntry = (i: number) => setDecEntries((prev) => prev.filter((_, idx) => idx !== i));
  const applyGlobal = () => {
    setEntries((prev) => prev.map((e) => ({ ...e, keyId: e.keyId || globalKeyId })));
  };

  const importText = (text: string) => {
    let imported: BatchEntry[];
    try {
      const parsed = JSON.parse(text);
      const rows = Array.isArray(parsed) ? parsed : parsed.entries;
      if (!Array.isArray(rows)) throw new Error("JSON must be an array or contain entries");
      imported = rows.map((row) => ({ keyId: row.key_id ?? row.keyId ?? "", plaintext: row.plaintext ?? "", aad: row.aad ?? row.aad_b64 ?? "", aadMode: row.aad_mode ?? (row.aad_b64 ? "base64" : "utf8") }));
    } catch {
      const lines = text.trim().split(/\r?\n/).filter(Boolean);
      const dataLines = lines[0]?.toLowerCase().startsWith("envelope,") ? lines.slice(1) : lines;
      imported = dataLines.map((line) => {
        const [keyId = "", plaintext = "", aad = "", aadMode = "utf8"] = line.split(",");
        if (!(["utf8", "base64", "hex"] as string[]).includes(aadMode)) throw new Error(`unsupported AAD mode: ${aadMode}`);
        return { keyId, plaintext, aad, aadMode: aadMode as AADMode };
      });
    }
    if (!imported.length || imported.length > 100) throw new Error("import must contain 1-100 entries");
    setEntries(imported); setResults(null); showToast(`imported ${imported.length} entries`, "success");
  };

  const importDecryptText = (text: string) => {
    let imported: BatchDecryptEntry[];
    try {
      const parsed = JSON.parse(text);
      const rows = Array.isArray(parsed) ? parsed : parsed.entries;
      if (!Array.isArray(rows)) throw new Error("JSON must be an array or contain entries");
      imported = rows.map((row) => ({ envelope: JSON.stringify(row.envelope ?? row, null, 2), aad: row.aad ?? row.aad_b64 ?? "", aadMode: row.aad_mode ?? (row.aad_b64 ? "base64" : "utf8") }));
    } catch {
      const lines = text.trim().split(/\r?\n/).filter(Boolean);
      const dataLines = lines[0]?.toLowerCase().startsWith("envelope,") ? lines.slice(1) : lines;
      imported = dataLines.map((line) => {
        const [envelope = "", aad = "", aadMode = "utf8"] = line.split(",");
        if (!(["utf8", "base64", "hex"] as string[]).includes(aadMode)) throw new Error(`unsupported AAD mode: ${aadMode}`);
        return { envelope, aad, aadMode: aadMode as AADMode };
      });
    }
    if (!imported.length || imported.length > 100) throw new Error("import must contain 1-100 entries");
    if (imported.some((entry) => !entry.envelope.trim())) throw new Error("each entry requires envelope");
    setDecEntries(imported); setDecResults(null); showToast(`imported ${imported.length} decrypt entries`, "success");
  };

  const encBatchMut = useMutation({
    mutationFn: () => {
      const payload = {
        tenant_id: tenantId,
        entries: entries.map((e) => ({
          key_id: e.keyId || globalKeyId,
          plaintext: toBase64(e.plaintext),
          aad_b64: encodeAAD(e.aad, e.aadMode),
        })),
      };
      return api.post<{ results: BatchResult[] }>(apiPaths.crypto.encryptBatch, payload);
    },
    onSuccess: (r) => {
      setResults(r.results);
      showToast(`batch encrypt: ${r.results.filter((x) => x.success).length}/${r.results.length} succeeded`, "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const decBatchMut = useMutation({
    mutationFn: () => {
      const payload = {
        tenant_id: tenantId,
        entries: decEntries.map((e) => ({
          envelope: JSON.parse(e.envelope),
          aad_b64: encodeAAD(e.aad, e.aadMode),
        })),
      };
      return api.post<{ results: BatchResult[] }>(apiPaths.crypto.decryptBatch, payload);
    },
    onSuccess: (r) => {
      setDecResults(r.results);
      showToast(`batch decrypt: ${r.results.filter((x) => x.success).length}/${r.results.length} succeeded`, "success");
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Batch Crypto</h1>
          <p className="section-subtitle">Bulk data-plane cryptographic operations with per-entry success and error reporting</p>
        </div>
      </div>

      <div className="grid-2 page-section">
        {/* Batch Encrypt */}
        <Panel title="Batch Encrypt">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {keysError && <ErrorState message={keysError.message} />}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div>
                <label className="input-label">Global Key (fallback)</label>
                <input
                  className="input"
                  list="batch-key-options"
                  value={globalKeyId}
                  onChange={(e) => setGlobalKeyId(e.target.value)}
                  placeholder="key_id or per-entry"
                />
                <datalist id="batch-key-options">
                  {keys.map((k) => (
                    <option key={k.key_id} value={k.key_id}>{k.name} ({k.suite_id})</option>
                  ))}
                </datalist>
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={applyGlobal} style={{ alignSelf: "flex-start" }}>
              Apply globals to all entries
            </button>
            <div className="toolbar-row">
              <button className="btn btn-ghost btn-sm" onClick={() => { setEntries([]); setResults(null); }}>Clear</button>
              <button className="btn btn-ghost btn-sm" onClick={() => { const text = prompt("Paste JSON array or CSV lines: key_id,plaintext,aad,aad_mode"); if (text) try { importText(text); } catch (e) { showToast((e as Error).message, "error"); } }}><Upload size={12} /> Paste JSON/CSV</button>
              <label className="btn btn-ghost btn-sm"><Upload size={12} /> Import file<input type="file" accept=".json,.csv,text/csv,application/json" hidden onChange={(e) => { const file = e.target.files?.[0]; if (file) file.text().then(importText).catch((err) => showToast(err.message, "error")); e.currentTarget.value = ""; }} /></label>
            </div>

            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
              {entries.map((e, i) => (
                <div key={i} style={{ padding: 10, marginBottom: 8, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 2 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>entry #{i}</span>
                    <button className="btn btn-ghost btn-sm" onClick={() => removeEntry(i)} style={{ padding: 2 }}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <input className="input" placeholder="plaintext..." value={e.plaintext} onChange={(ev) => updateEntry(i, { plaintext: ev.target.value })} />
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                      <input
                        className="input"
                        list="batch-key-options"
                        placeholder="key_id (or global)"
                        value={e.keyId}
                        onChange={(ev) => updateEntry(i, { keyId: ev.target.value })}
                      />
                    </div>
                    <div className="aad-input-row"><select className="select" value={e.aadMode} onChange={(ev) => updateEntry(i, { aadMode: ev.target.value as AADMode })}><option value="utf8">UTF-8</option><option value="base64">Base64</option><option value="hex">Hex</option></select><input className="input" placeholder={`AAD (${e.aadMode})`} value={e.aad} onChange={(ev) => updateEntry(i, { aad: ev.target.value })} /></div>
                  </div>
                </div>
              ))}
              <button className="btn btn-ghost btn-sm" onClick={addEntry} style={{ marginTop: 4 }}>
                <Plus size={12} /> Add Entry
              </button>
            </div>

            <button
              className="btn btn-primary"
              disabled={entries.length === 0 || encBatchMut.isPending}
              onClick={() => encBatchMut.mutate()}
            >
              <Lock size={14} /> {encBatchMut.isPending ? "Encrypting..." : `Encrypt Batch (${entries.length})`}
            </button>

            {results && (
              <div style={{ marginTop: 4 }}>
                <div className="input-label" style={{ marginBottom: 8 }}>Results</div>
                <div className="toolbar-row"><span className="mono">{results.filter((r) => r.success).length} succeeded · {results.filter((r) => !r.success).length} failed</span><button className="btn btn-ghost btn-sm" onClick={() => setFailedOnly(!failedOnly)}>{failedOnly ? "Show all" : "Failures only"}</button><button className="btn btn-ghost btn-sm" disabled={!results.some((r) => r.success)} onClick={() => { navigator.clipboard.writeText(JSON.stringify(results.filter((r) => r.success).map((r) => ({ envelope: r.envelope })), null, 2)); showToast("copied successful envelopes", "success"); }}><Copy size={12} /> Copy successes</button>{results.some((r) => !r.success) && <button className="btn btn-ghost btn-sm" onClick={() => { setEntries(results.filter((r) => !r.success).map((r) => entries[r.index])); setResults(null); }}><RotateCcw size={12} /> Retry failures</button>}</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {results.filter((r) => !failedOnly || !r.success).map((r) => (
                    <div key={r.index} style={{ padding: 8, background: "var(--bg-inset)", border: `1px solid ${r.success ? "var(--success)" : "var(--danger)"}`, borderRadius: 2 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        {r.success ? <CheckCircle size={12} style={{ color: "var(--success)" }} /> : <XCircle size={12} style={{ color: "var(--danger)" }} />}
                        <span className="mono" style={{ fontSize: 11, fontWeight: 600 }}>#{r.index}</span>
                        {r.suite_id && <SuiteBadge suite={r.suite_id} />}
                        {r.key_id && <span className="mono" style={{ fontSize: 10, color: "var(--text-tertiary)" }}>v{r.key_version}</span>}
                        {r.error_code && <span className="mono" style={{ fontSize: 10, color: "var(--danger)" }}>{r.error_code}: {r.message}</span>}
                      </div>
                      {r.envelope && (
                        <MonoReadout value={JSON.stringify(r.envelope, null, 2)} copyable />
                      )}
                    </div>
                  ))}
                </div>
                {results.some((r) => r.success) && (
                  <button
                    className="btn btn-ghost btn-sm"
                    style={{ marginTop: 8 }}
                    onClick={() => {
                      setDecEntries(results.filter((r) => r.success).map((r) => ({
                        envelope: JSON.stringify(r.envelope ?? {}, null, 2),
                        aad: entries[r.index].aad, aadMode: entries[r.index].aadMode,
                      })));
                      showToast("sent to decrypt batch", "info");
                    }}
                  >
                    <Play size={12} /> Send envelopes to Batch Decrypt
                  </button>
                )}
              </div>
            )}
          </div>
        </Panel>

        {/* Batch Decrypt */}
        <Panel title="Batch Decrypt">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="toolbar-row">
              <button className="btn btn-ghost btn-sm" onClick={() => { setDecEntries([]); setDecResults(null); }}>Clear</button>
              <button className="btn btn-ghost btn-sm" onClick={() => { const text = prompt("Paste JSON array or CSV lines: envelope,aad,aad_mode"); if (text) try { importDecryptText(text); } catch (error) { showToast((error as Error).message, "error"); } }}><Upload size={12} /> Paste JSON/CSV</button>
              <label className="btn btn-ghost btn-sm"><Upload size={12} /> Import file<input type="file" accept=".json,.csv,text/csv,application/json" hidden onChange={(event) => { const file = event.target.files?.[0]; if (file) file.text().then(importDecryptText).catch((error) => showToast(error.message, "error")); event.currentTarget.value = ""; }} /></label>
            </div>
            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
              {decEntries.map((e, i) => (
                <div key={i} style={{ padding: 10, marginBottom: 8, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 2 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>entry #{i}</span>
                    <button className="btn btn-ghost btn-sm" onClick={() => removeDecEntry(i)} style={{ padding: 2 }}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <textarea
                      className="textarea"
                      value={e.envelope}
                      onChange={(ev) => updateDecEntry(i, { envelope: ev.target.value })}
                      placeholder="envelope JSON..."
                      style={{ minHeight: 72, fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}
                    />
                    <div className="aad-input-row"><select className="select" value={e.aadMode} onChange={(ev) => updateDecEntry(i, { aadMode: ev.target.value as AADMode })}><option value="utf8">UTF-8</option><option value="base64">Base64</option><option value="hex">Hex</option></select><input className="input" placeholder={`AAD (${e.aadMode})`} value={e.aad} onChange={(ev) => updateDecEntry(i, { aad: ev.target.value })} /></div>
                  </div>
                </div>
              ))}
              <button className="btn btn-ghost btn-sm" onClick={addDecEntry} style={{ marginTop: 4 }}>
                <Plus size={12} /> Add Entry
              </button>
            </div>
            <button
              className="btn btn-primary"
              disabled={decEntries.length === 0 || decEntries.every((e) => !e.envelope.trim()) || decBatchMut.isPending}
              onClick={() => decBatchMut.mutate()}
            >
              <Unlock size={14} /> {decBatchMut.isPending ? "Decrypting..." : "Decrypt Batch"}
            </button>

            {decResults && (
              <div style={{ marginTop: 4 }}>
                <div className="input-label" style={{ marginBottom: 8 }}>Results</div>
                <div className="toolbar-row"><span className="mono">{decResults.filter((r) => r.success).length} succeeded · {decResults.filter((r) => !r.success).length} failed</span><button className="btn btn-ghost btn-sm" onClick={() => { navigator.clipboard.writeText(decResults.filter((r) => r.success && r.plaintext).map((r) => fromBase64(r.plaintext!)).join("\n")); showToast("copied successful plaintexts", "success"); }}><Copy size={12} /> Copy successes</button></div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {decResults.map((r) => (
                    <div key={r.index} style={{ padding: 8, background: "var(--bg-inset)", border: `1px solid ${r.success ? "var(--success)" : "var(--danger)"}`, borderRadius: 2 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        {r.success ? <CheckCircle size={12} style={{ color: "var(--success)" }} /> : <XCircle size={12} style={{ color: "var(--danger)" }} />}
                        <span className="mono" style={{ fontSize: 11, fontWeight: 600 }}>#{r.index}</span>
                        {r.key_id && <span className="mono" style={{ fontSize: 10, color: "var(--text-tertiary)" }}>{r.key_id.slice(0, 16)}... v{r.key_version}</span>}
                        {r.error_code && <span className="mono" style={{ fontSize: 10, color: "var(--danger)" }}>{r.error_code}: {r.message}</span>}
                      </div>
                      {r.plaintext && (
                        <MonoReadout value={fromBase64(r.plaintext)} copyable />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Panel>
      </div>

      <Panel title="Batch API Contract">
        <div style={{ display: "flex", flexDirection: "column", gap: 10, fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: "var(--text-secondary)" }}>
          <div>
            <span style={{ color: "var(--accent)" }}>POST</span> /ui/api/v1/crypto/encrypt-batch
          </div>
          <pre style={{ margin: 0, padding: 10, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 2, whiteSpace: "pre-wrap" }}>
{`{
  "tenant_id": "t-default",
  "entries": [
    {
      "key_id": "...",
      "plaintext": "<base64>",
      "aad_b64": "<base64 caller AAD bytes>"
    }
  ]
}`}
          </pre>
          <div style={{ marginTop: 8 }}>
            <span style={{ color: "var(--accent)" }}>POST</span> /ui/api/v1/crypto/decrypt-batch
          </div>
          <pre style={{ margin: 0, padding: 10, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 2, whiteSpace: "pre-wrap" }}>
{`{
  "tenant_id": "t-default",
  "entries": [ { "envelope": { "version": 1, "suite_id": "AES_256_ECB", "...": "..." }, "aad_b64": "<base64 caller AAD bytes>" } ]
}`}
          </pre>
          <div style={{ marginTop: 8, color: "var(--text-tertiary)" }}>
            Constraints: max 100 entries per batch; per-entry success/error_code; base64 plaintext and aad_b64
          </div>
        </div>
      </Panel>
    </PageContainer>
  );
}


