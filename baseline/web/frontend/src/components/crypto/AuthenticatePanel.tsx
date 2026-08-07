import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";
import { useAuth } from "../../lib/store";
import { toBase64 } from "../../lib/envelope";
import type { AuthenticateResponse, Authenticator, KeyDTO, VerifyResponse } from "../../lib/types";
import { MonoReadout, Panel, showToast, SuiteBadge } from "../index";

interface Props {
  keys: KeyDTO[];
}

export function AuthenticatePanel({ keys }: Props) {
  const { tenantId } = useAuth();
  const [keyId, setKeyId] = useState("");
  const [message, setMessage] = useState("message to authenticate");
  const [authenticator, setAuthenticator] = useState<Authenticator | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);

  const authenticate = useMutation({
    mutationFn: () => api.post<AuthenticateResponse>(apiPaths.crypto.authenticate, {
      tenant_id: tenantId,
      key_id: keyId,
      message: toBase64(message),
    }),
    onSuccess: (result) => {
      setAuthenticator(result.authenticator);
      setValid(null);
      showToast("CMAC authenticator created", "success");
    },
    onError: (error: Error) => showToast(error.message, "error"),
  });

  const verify = useMutation({
    mutationFn: () => api.post<VerifyResponse>(apiPaths.crypto.verify, {
      tenant_id: tenantId,
      message: toBase64(message),
      authenticator,
    }),
    onSuccess: (result) => {
      setValid(result.valid);
      showToast(result.valid ? "authenticator valid" : "authenticator mismatch", result.valid ? "success" : "error");
    },
    onError: (error: Error) => showToast(error.message, "error"),
  });

  return (
    <Panel title="Authenticate / Verify (CMAC)">
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div>
          <label className="input-label">Authentication key</label>
          <select className="select" value={keyId} onChange={(event) => setKeyId(event.target.value)}>
            <option value="">select authenticate_verify key</option>
            {keys.map((key) => (
              <option key={key.key_id} value={key.key_id}>{key.name} ({key.suite_id})</option>
            ))}
          </select>
        </div>
        <div>
          <label className="input-label">Message (returned unchanged)</label>
          <textarea className="textarea" value={message} onChange={(event) => setMessage(event.target.value)} />
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" disabled={!keyId || authenticate.isPending} onClick={() => authenticate.mutate()}>
            <ShieldCheck size={14} /> Authenticate
          </button>
          <button className="btn btn-secondary" disabled={!authenticator || verify.isPending} onClick={() => verify.mutate()}>
            Verify
          </button>
        </div>
        {authenticator && (
          <>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <SuiteBadge suite={authenticator.suite_id} />
              <span className="mono" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
                key v{authenticator.key_version} · policy v{authenticator.policy_version}
              </span>
            </div>
            <MonoReadout label="Detached authenticator JSON" value={JSON.stringify(authenticator, null, 2)} copyable />
          </>
        )}
        {valid !== null && (
          <div style={{ color: valid ? "var(--success)" : "var(--danger)", fontWeight: 600 }}>
            {valid ? "VALID" : "INVALID"}
          </div>
        )}
      </div>
    </Panel>
  );
}
