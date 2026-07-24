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
  const [purpose, setPurpose] = useState<"encrypt_decrypt" | "key_wrap">("encrypt_decrypt");
  const [externalKey, setExternalKey] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState("");

  const expectedBytes = suiteKeyBytes[suite] ?? 32;
  const availableSuites = purpose === "key_wrap"
    ? SYMMETRIC_SUITES.filter((item) => item.id === "AES_256_GCM" || item.id === "SM4_GCM")
    : SYMMETRIC_SUITES;

  // Validate base64 and length.
  let dekValid = false;
  let dekError = "";
  if (externalKey.trim()) {
    try {
      const decoded = atob(externalKey.trim());
      if (decoded.length !== expectedBytes) {
        dekError = `length mismatch: got ${decoded.length} bytes, expected ${expectedBytes}`;
      } else {
        dekValid = true;
      }
    } catch {
      dekError = "not valid base64";
    }
  }
  const keyTerm = purpose === "key_wrap"
    ? "Key Encryption Key (KEK)"
    : "Data Encryption Key (DEK)";

  return (
    <Modal title="Import External Key (Controlled Import)" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ padding: "10px 12px", background: "var(--danger-dim)", border: "1px solid var(--danger)", borderRadius: 2, fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.6 }}>
          <strong style={{ color: "var(--danger)" }}>Note:</strong> The imported {keyTerm} material is sealed under the
          Cryptographic Root Key (CRK) and zeroized immediately. It is never persisted in plaintext, logged, or returned.
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
          <select className="select" value={purpose} onChange={(event) => {
            const next = event.target.value as "encrypt_decrypt" | "key_wrap";
            setPurpose(next);
            if (next === "key_wrap" && suite !== "AES_256_GCM" && suite !== "SM4_GCM") {
              setSuite("SM4_GCM");
            }
          }}>
            <option value="encrypt_decrypt">Data Encryption Key (DEK)</option>
            <option value="key_wrap">Key Encryption Key (KEK)</option>
          </select>
          <div style={{ marginTop: 5, fontSize: 11, color: "var(--text-tertiary)" }}>
            {purpose === "key_wrap"
              ? "Used only to protect keys during Key Upload and Key Download."
              : "Used for application data encryption and decryption."}
          </div>
        </div>
        <div>
          <label className="input-label">Suite</label>
          <select className="select" value={suite} onChange={(e) => setSuite(e.target.value)}>
            {availableSuites.map((item) => <option key={item.id} value={item.id}>{item.id} ({item.keyBytes} bytes)</option>)}
          </select>
        </div>
        <div>
          <label className="input-label">Expires At (optional)</label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
        </div>
        <div>
          <label className="input-label">{keyTerm} material (base64, {expectedBytes} bytes)</label>
          <textarea
            className="textarea"
            value={externalKey}
            onChange={(e) => setExternalKey(e.target.value)}
            placeholder={`paste base64-encoded ${expectedBytes}-byte key material...`}
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
              purpose,
              policy_id: policyID!,
              suite_id: suite,
              expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
              external_key: externalKey.trim(),
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
