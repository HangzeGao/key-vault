import { useState } from "react";
import { Upload, CheckCircle, XCircle } from "lucide-react";
import { Modal, showToast } from "../index";
import type { BatchImportKeyResult, ImportKeyReq } from "../../lib/types";

interface Props {
  onClose: () => void;
  onImport: (entries: ImportKeyReq[]) => Promise<{ results: BatchImportKeyResult[] }>;
  policyID?: string;
}

function parseEntries(text: string, policyID: string): ImportKeyReq[] {
  let rows: Array<Record<string, string>>;
  try {
    const parsed = JSON.parse(text);
    rows = Array.isArray(parsed) ? parsed : parsed.entries;
    if (!Array.isArray(rows)) throw new Error("JSON must be an array or contain entries");
  } catch {
    const lines = text.trim().split(/\r?\n/).filter(Boolean);
    const dataLines = lines[0]?.toLowerCase().startsWith("name,") ? lines.slice(1) : lines;
    rows = dataLines.map((line) => {
      const [name = "", key_id = "", suite_id = "AES_256_GCM", external_dek = "", expires_at = ""] = line.split(",");
      return { name, key_id, suite_id, external_dek, expires_at };
    });
  }
  const entries = rows.map((row) => ({
    tenant_id: row.tenant_id ?? "",
    name: row.name ?? "",
    key_id: row.key_id || row.keyId || undefined,
    purpose: "encrypt_decrypt",
    policy_id: policyID,
    suite_id: row.suite_id || row.suiteId || "AES_256_GCM",
    external_dek: row.external_dek || row.externalDEK || "",
    expires_at: row.expires_at || row.expiresAt || undefined,
  }));
  if (entries.length === 0 || entries.length > 100) throw new Error("import must contain 1-100 entries");
  if (entries.some((entry) => !entry.name.trim() || !entry.external_dek.trim())) throw new Error("each entry requires name and external_dek");
  return entries;
}

export function BatchImportKeyModal({ onClose, onImport, policyID }: Props) {
  const [source, setSource] = useState("");
  const [results, setResults] = useState<BatchImportKeyResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const submit = async () => {
    try {
      if (!policyID) throw new Error("active policy is unavailable");
      const entries = parseEntries(source, policyID);
      setLoading(true);
      const response = await onImport(entries);
      setResults(response.results);
      showToast(`key import: ${response.results.filter((r) => r.success).length}/${response.results.length} succeeded`, "success");
    } catch (error) {
      showToast((error as Error).message, "error");
    } finally {
      setLoading(false);
    }
  };
  return (
    <Modal title="Batch Import Keys" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div className="batch-import-warning">External DEKs are sealed in the key plane and are never returned. CSV columns: <code>name,key_id,suite_id,external_dek,expires_at</code>.</div>
        <textarea className="textarea" value={source} onChange={(event) => setSource(event.target.value)} placeholder='Paste JSON entries or CSV rows. Example: {"name":"orders","suite_id":"AES_256_GCM","external_dek":"..."}' style={{ minHeight: 190, fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }} />
        <label className="btn btn-ghost btn-sm" style={{ alignSelf: "flex-start" }}><Upload size={12} /> Import JSON/CSV file<input hidden type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) file.text().then(setSource).catch((error) => showToast(error.message, "error")); event.currentTarget.value = ""; }} /></label>
        <button className="btn btn-primary" disabled={!source.trim() || !policyID || loading} onClick={submit}>{loading ? "Importing..." : "Import up to 100 Keys"}</button>
        {results && <div className="batch-import-results">{results.map((result) => <div key={result.index} className={result.success ? "batch-import-result success" : "batch-import-result failure"}>{result.success ? <CheckCircle size={13} /> : <XCircle size={13} />}<span>#{result.index}</span><strong>{result.success ? result.key?.name ?? result.key?.key_id : result.error_code}</strong><small>{result.success ? result.key?.key_id : result.message}</small></div>)}</div>}
      </div>
    </Modal>
  );
}
