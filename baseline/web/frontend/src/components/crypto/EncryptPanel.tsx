import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Lock, ArrowRight } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";
import { useAuth } from "../../lib/store";
import { Panel, SuiteBadge, MonoReadout, showToast } from "../index";
import { toBase64 } from "../../lib/envelope";
import type { KeyDTO, EncryptResponse } from "../../lib/types";

interface Props {
  keys: KeyDTO[];
  formatOptions: string[];
  onSendToDecrypt: (ciphertext: string, aad: string, format: string) => void;
}

export function EncryptPanel({ keys, formatOptions, onSendToDecrypt }: Props) {
  const { tenantId } = useAuth();
  const [keyId, setKeyId] = useState("");
  const [plaintext, setPlaintext] = useState("hello, cryogenic vault");
  const [encAAD, setEncAAD] = useState("{\"source\":\"partner-a\",\"object\":\"order-123\"}");
  const [encExtensions, setEncExtensions] = useState("{\n  \"trace_id\": \"trace-001\"\n}");
  const [encResult, setEncResult] = useState<EncryptResponse | null>(null);
  const [envelopeFormat, setEnvelopeFormat] = useState("");

  const parseExtensions = () => {
    const raw = encExtensions.trim();
    if (!raw) return undefined;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
      throw new Error("extensions must be a JSON object");
    }
    return parsed;
  };

  const encMut = useMutation({
    mutationFn: () => {
      let extensions: Record<string, unknown> | undefined;
      try {
        extensions = parseExtensions();
      } catch (e) {
        throw new Error(e instanceof Error ? e.message : "invalid JSON input");
      }
      return api.post<EncryptResponse>(apiPaths.crypto.encrypt, {
        tenant_id: tenantId,
        key_id: keyId,
        plaintext: toBase64(plaintext),
        aad_b64: encAAD ? toBase64(encAAD) : undefined,
        envelope_format: envelopeFormat || undefined,
        extensions,
      });
    },
    onSuccess: (r) => { setEncResult(r); showToast("encrypted", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  return (
    <Panel title="Encrypt">
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <label className="input-label">Key</label>
          <input
            className="input"
            list="crypto-key-options"
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            placeholder="key_id"
          />
          <datalist id="crypto-key-options">
            {keys.map((k) => (
              <option key={k.key_id} value={k.key_id}>
                {k.name} ({k.suite_id})
              </option>
            ))}
          </datalist>
        </div>
        <div>
          <label className="input-label">Plaintext</label>
          <textarea
            className="textarea"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            placeholder="enter plaintext..."
          />
        </div>
        <div>
          <label className="input-label">Envelope Format (optional, uses tenant default if empty)</label>
          <select className="select" value={envelopeFormat} onChange={(e) => setEnvelopeFormat(e.target.value)}>
            <option value="">tenant default</option>
            {formatOptions.map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="input-label">AAD bytes (UTF-8, sent as aad_b64)</label>
          <textarea
            className="textarea mono"
            value={encAAD}
            onChange={(e) => setEncAAD(e.target.value)}
            placeholder="caller canonical AAD bytes"
            style={{ minHeight: 84 }}
          />
        </div>
        <div>
          <label className="input-label">Extensions JSON</label>
          <textarea
            className="textarea mono"
            value={encExtensions}
            onChange={(e) => setEncExtensions(e.target.value)}
            placeholder="{ &quot;trace_id&quot;: &quot;trace-001&quot; }"
            style={{ minHeight: 84 }}
          />
        </div>
        <button className="btn btn-primary" disabled={!keyId || encMut.isPending} onClick={() => encMut.mutate()}>
          <Lock size={14} /> {encMut.isPending ? "Encrypting..." : "Encrypt"}
        </button>
        {encResult && (
          <div style={{ marginTop: 4 }}>
            <div style={{ display: "flex", gap: 8, marginBottom: 10, alignItems: "center" }}>
              <SuiteBadge suite={encResult.suite_id} />
              <span className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                key v{encResult.key_version}
              </span>
              {encResult.envelope_format && (
                <span className="mono" style={{ fontSize: 10, color: "var(--accent)" }}>
                  {encResult.envelope_format}
                </span>
              )}
            </div>
            <MonoReadout label="Ciphertext (base64 envelope)" value={encResult.ciphertext} copyable />
            <button
              className="btn btn-ghost btn-sm"
              style={{ marginTop: 8 }}
              onClick={() => onSendToDecrypt(encResult.ciphertext, encAAD, encResult.envelope_format ?? envelopeFormat)}
            >
              <ArrowRight size={12} /> Send to decrypt
            </button>
          </div>
        )}
      </div>
    </Panel>
  );
}
