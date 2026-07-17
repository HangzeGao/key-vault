import { useState } from "react";
import { Modal } from "../index";
import type { CreateKeyReq } from "../../lib/types";
import { SYMMETRIC_SUITES } from "../../lib/suites";

interface Props {
  onClose: () => void;
  onCreate: (req: CreateKeyReq, idempotencyKey?: string) => void;
  loading: boolean;
  policyID?: string;
}

export function CreateKeyModal({ onClose, onCreate, loading, policyID }: Props) {
  const [name, setName] = useState("");
  const [keyId, setKeyId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [suite, setSuite] = useState("AES_256_GCM");
  const [idempotencyKey, setIdempotencyKey] = useState("");

  return (
    <Modal title="Create Key" onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <label className="input-label">Name</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="my-app-key" autoFocus />
        </div>
        <div>
          <label className="input-label">Key ID (optional)</label>
          <input className="input" value={keyId} onChange={(e) => setKeyId(e.target.value)} placeholder="key_customer_orders" />
        </div>
        <div>
          <label className="input-label">Purpose</label>
          <div className="input input-static">encrypt_decrypt <span>Symmetric encryption only</span></div>
        </div>
        <div>
          <label className="input-label">Suite</label>
          <select className="select" value={suite} onChange={(e) => setSuite(e.target.value)}>
            {SYMMETRIC_SUITES.map((item) => <option key={item.id} value={item.id}>{item.id}</option>)}
          </select>
        </div>
        <div>
          <label className="input-label">Expires At (optional)</label>
          <input className="input" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
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
          disabled={!name.trim() || !policyID || loading}
          onClick={() => onCreate(
            {
              tenant_id: "",
              key_id: keyId.trim() || undefined,
              name: name.trim(),
              purpose: "encrypt_decrypt",
              policy_id: policyID!,
              suite_id: suite,
              expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
            },
            idempotencyKey.trim() || undefined,
          )}
        >
          {loading ? "Creating..." : "Create"}
        </button>
      </div>
    </Modal>
  );
}
