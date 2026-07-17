import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { Unlock } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";
import { useAuth } from "../../lib/store";
import { Panel, MonoReadout, showToast } from "../index";
import { toBase64, fromBase64 } from "../../lib/envelope";
import type { DecryptResponse } from "../../lib/types";

interface Props {
  formatOptions: string[];
  seedCiphertext?: string;
  seedAAD?: string;
  seedFormat?: string;
  seedVersion?: number; // 用于触发重新初始化
}

export function DecryptPanel({ formatOptions, seedCiphertext, seedAAD, seedFormat, seedVersion }: Props) {
  const { tenantId } = useAuth();
  const [decCiphertext, setDecCiphertext] = useState("");
  const [decAAD, setDecAAD] = useState("");
  const [decEnvelopeFormat, setDecEnvelopeFormat] = useState("");
  const [decResult, setDecResult] = useState<DecryptResponse | null>(null);

  // 当 seedVersion 变化时（Encrypt → Send to decrypt），同步初始值
  useEffect(() => {
    if (seedVersion !== undefined && seedVersion > 0) {
      if (seedCiphertext !== undefined) setDecCiphertext(seedCiphertext);
      if (seedAAD !== undefined) setDecAAD(seedAAD);
      if (seedFormat !== undefined) setDecEnvelopeFormat(seedFormat);
      setDecResult(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seedVersion]);

  const decMut = useMutation({
    mutationFn: () =>
      api.post<DecryptResponse>(apiPaths.crypto.decrypt, {
        tenant_id: tenantId,
        ciphertext: decCiphertext,
        aad_b64: decAAD ? toBase64(decAAD) : undefined,
        envelope_format: decEnvelopeFormat || undefined,
      }),
    onSuccess: (r) => { setDecResult(r); showToast("decrypted", "success"); },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  return (
    <Panel title="Decrypt">
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <label className="input-label">Ciphertext (base64)</label>
          <textarea
            className="textarea"
            value={decCiphertext}
            onChange={(e) => setDecCiphertext(e.target.value)}
            placeholder="paste base64 envelope..."
            style={{ minHeight: 100 }}
          />
        </div>
        <div>
          <label className="input-label">AAD bytes (UTF-8, sent as aad_b64)</label>
          <textarea
            className="textarea mono"
            value={decAAD}
            onChange={(e) => setDecAAD(e.target.value)}
            placeholder="must match encryption AAD exactly"
            style={{ minHeight: 84 }}
          />
        </div>
        <div>
          <label className="input-label">Envelope Format</label>
          <select className="select" value={decEnvelopeFormat} onChange={(e) => setDecEnvelopeFormat(e.target.value)}>
            <option value="">auto-detect</option>
            {formatOptions.map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
        </div>
        <button className="btn btn-primary" disabled={!decCiphertext || decMut.isPending} onClick={() => decMut.mutate()}>
          <Unlock size={14} /> {decMut.isPending ? "Decrypting..." : "Decrypt"}
        </button>
        {decResult && (
          <div style={{ marginTop: 4 }}>
            <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
              <span className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                key: {decResult.key_id.slice(0, 16)}... v{decResult.key_version}
              </span>
            </div>
            <MonoReadout label="Plaintext (decoded)" value={fromBase64(decResult.plaintext)} copyable />
            <div style={{ marginTop: 8 }}>
              <MonoReadout label="Plaintext (base64)" value={decResult.plaintext} copyable />
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}
