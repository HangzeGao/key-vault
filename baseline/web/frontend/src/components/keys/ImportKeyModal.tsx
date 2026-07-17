import { useState } from "react";
import { Modal } from "../index";
import type { ImportKeyReq } from "../../lib/types";
import { SYMMETRIC_SUITES, suiteKeyBytes } from "../../lib/suites";

interface Props {
  onClose: () => void;
  onImport: (req: ImportKeyReq, idempotencyKey?: string) => void;
  loading: boolean;
  policyID?: string;
}

export function ImportKeyModal({ onClose, onImport, loading, policyID }: Props) {
  const [name, setName] = useState("");
  const [keyId, setKeyId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [suite, setSuite] = useState("AES_256_GCM");
  const [externalDEK, setExternalDEK] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState("");

  const expectedBytes = suiteKeyBytes[suite] ?? 32;

  // Validate base64 and length.
  let dekValid = false;
  let dekError = "";
  if (externalDEK.trim()) {
    try {
      const decoded = atob(externalDEK.trim());
      if (decoded.length !== expectedBytes) {
        dekError = `length mismatch: got ${decoded.length} bytes, expected ${expectedBytes}`;
      } else {
        dekValid = true;
      }
    } catch {
      dekError = "not valid base64";
    }
  }

  return (
    <Modal title="Import External Key (Controlled Import)" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ padding: "10px 12px", background: "var(--danger-dim)", border: "1px solid var(--danger)", borderRadius: 2, fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.6 }}>
          <strong style={{ color: "var(--danger)" }}>Note:</strong> The external DEK plaintext is sealed under the CRK
          in the key plane and zeroized immediately. It is never persisted, logged, or returned in the response.
        </div>
        <div>
          <label className="input-label">Name</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="imported-key" autoFocus />
        </div>
        <div>
          <label className="input-label">Key ID (optional)</label>
          <input className="input" value={keyId} onChange={(e) => setKeyId(e.target.value)} placeholder="key_imported_01" />
        </div>
        <div>
          <label className="input-label">Purpose</label>
          <div className="input input-static">encrypt_decrypt <span>Symmetric encryption only</span></div>
        </div>
        <div>
          <label className="input-label">Suite</label>
          <select className="select" value={suite} onChange={(e) => setSuite(e.target.value)}>
            {SYMMETRIC_SUITES.map((item) => <option key={item.id} value={item.id}>{item.id} ({item.keyBytes} bytes)</option>)}
          </select>
        </div>
        <div>
          <label className="input-label">Expires At (optional)</label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </div>
        <div>
          <label className="input-label">External DEK (base64, {expectedBytes} bytes)</label>
          <textarea
            className="textarea"
            value={externalDEK}
            onChange={(e) => setExternalDEK(e.target.value)}
            placeholder={`paste base64-encoded ${expectedBytes}-byte DEK...`}
            style={{ minHeight: 60, fontFamily: '"JetBrains Mono", monospace', fontSize: 11 }}
          />
          {dekError && (
            <div style={{ marginTop: 4, fontSize: 11, color: "var(--danger)", fontFamily: '"JetBrains Mono", monospace' }}>
              {dekError}
            </div>
          )}
          {dekValid && (
            <div style={{ marginTop: 4, fontSize: 11, color: "var(--success)", fontFamily: '"JetBrains Mono", monospace' }}>
              valid: {expectedBytes} bytes
            </div>
          )}
        </div>
        <div>
          <label className="input-label">Idempotency Key (optional)</label>
          <input
            className="input"
            value={idempotencyKey}
            onChange={(e) => setIdempotencyKey(e.target.value)}
            placeholder="unique id for safe retry"
          />
        </div>
      </div>
      <div style={{ marginTop: 20, display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <button className="btn btn-secondary btn-sm" onClick={onClose}>Cancel</button>
        <button
          className="btn btn-primary btn-sm"
          disabled={!name.trim() || !dekValid || !policyID || loading}
          onClick={() => onImport(
            {
              tenant_id: "",
              key_id: keyId.trim() || undefined,
              name: name.trim(),
              purpose: "encrypt_decrypt",
              policy_id: policyID!,
              suite_id: suite,
              expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
              external_dek: externalDEK.trim(),
            },
            idempotencyKey.trim() || undefined,
          )}
        >
          {loading ? "Importing..." : "Import"}
        </button>
      </div>
    </Modal>
  );
}
