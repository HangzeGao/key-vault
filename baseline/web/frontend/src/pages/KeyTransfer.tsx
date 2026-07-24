import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDownToLine, ArrowUpFromLine, CheckCircle2, RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import { apiPaths, newIdempotencyKey } from "../lib/apiPaths";
import {
  ErrorState,
  KVList,
  Loading,
  MonoReadout,
  PageContainer,
  Panel,
  StatusPill,
  showToast,
} from "../components";
import type {
  CreateKeyUploadReq,
  ImportKeyDownloadReq,
  KeyDownloadDTO,
  KeyDTO,
  KeyUploadDTO,
  SignedPolicy,
} from "../lib/types";

type TransferMode = "upload" | "download";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label><span className="input-label">{label}</span>{children}</label>;
}

function toBase64(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function newDownloadID() {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `download-${suffix}`;
}

function UploadView({ keys }: { keys: KeyDTO[] }) {
  const [targetID, setTargetID] = useState("");
  const [sequence, setSequence] = useState("1");
  const [kekID, setKEKID] = useState("");
  const [kekVersion, setKEKVersion] = useState("");
  const [dataKeyID, setDataKeyID] = useState("");
  const [dataKeyVersion, setDataKeyVersion] = useState("");
  const [result, setResult] = useState<KeyUploadDTO | null>(null);

  const keks = keys.filter((key) => key.purpose === "key_wrap" && key.status === "ACTIVE" &&
    (key.suite_id === "AES_256_GCM" || key.suite_id === "SM4_GCM"));
  const dataKeys = keys.filter((key) => key.purpose === "encrypt_decrypt" && key.status === "ACTIVE" && key.suite_id === "SM4_GCM");

  const upload = useMutation({
    mutationFn: (req: CreateKeyUploadReq) =>
      api.post<KeyUploadDTO>(apiPaths.keyUploads, req, { "Idempotency-Key": newIdempotencyKey() }),
    onSuccess: (value) => {
      setResult(value);
      showToast("key upload created", "success");
    },
    onError: (error: Error) => showToast(error.message, "error"),
  });
  const confirm = useMutation({
    mutationFn: (uploadID: string) => api.post<KeyUploadDTO>(apiPaths.confirmKeyUpload(uploadID)),
    onSuccess: (value) => {
      setResult(value);
      showToast("key upload confirmed", "success");
    },
    onError: (error: Error) => showToast(error.message, "error"),
  });
  const refresh = useMutation({
    mutationFn: (uploadID: string) => api.get<KeyUploadDTO>(apiPaths.keyUpload(uploadID)),
    onSuccess: setResult,
    onError: (error: Error) => showToast(error.message, "error"),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const seq = Number(sequence);
    if (!targetID.trim() || !kekID || !dataKeyID || !Number.isSafeInteger(seq) || seq < 1) {
      showToast("target, sequence, KEK and data key are required", "error");
      return;
    }
    upload.mutate({
      target_id: targetID.trim(),
      sequence: seq,
      kek_id: kekID,
      kek_version: kekVersion ? Number(kekVersion) : undefined,
      data_key_id: dataKeyID,
      data_key_version: dataKeyVersion ? Number(dataKeyVersion) : undefined,
    });
  };

  return (
    <div className="grid-2 page-section">
      <Panel title="Create Key Upload">
        <form className="compact-stack" onSubmit={submit}>
          <div className="form-grid">
            <Field label="Device target">
              <input className="input" value={targetID} onChange={(event) => setTargetID(event.target.value)} placeholder="crypto-device-01" />
            </Field>
            <Field label="Replay sequence">
              <input className="input" type="number" min="1" value={sequence} onChange={(event) => setSequence(event.target.value)} />
            </Field>
            <Field label="KEK">
              <select className="select" value={kekID} onChange={(event) => {
                setKEKID(event.target.value);
                const selected = keks.find((key) => key.key_id === event.target.value);
                setKEKVersion(selected ? String(selected.current_version) : "");
              }}>
                <option value="">Select an active key-wrap key</option>
                {keks.map((key) => <option key={key.key_id} value={key.key_id}>{key.name} · {key.suite_id}</option>)}
              </select>
            </Field>
            <Field label="KEK version">
              <input className="input" type="number" min="1" value={kekVersion} onChange={(event) => setKEKVersion(event.target.value)} placeholder="current" />
            </Field>
            <Field label="SM4-GCM data key">
              <select className="select" value={dataKeyID} onChange={(event) => {
                setDataKeyID(event.target.value);
                const selected = dataKeys.find((key) => key.key_id === event.target.value);
                setDataKeyVersion(selected ? String(selected.current_version) : "");
              }}>
                <option value="">Select a data key</option>
                {dataKeys.map((key) => <option key={key.key_id} value={key.key_id}>{key.name} · v{key.current_version}</option>)}
              </select>
            </Field>
            <Field label="Data key version">
              <input className="input" type="number" min="1" value={dataKeyVersion} onChange={(event) => setDataKeyVersion(event.target.value)} placeholder="current" />
            </Field>
          </div>
          {keks.length === 0 && <div className="transfer-hint">Import an active <span className="mono">key_wrap</span> KEK before creating an upload.</div>}
          <button className="btn btn-primary" type="submit" disabled={upload.isPending || keks.length === 0 || dataKeys.length === 0}>
            <ArrowUpFromLine size={15} /> {upload.isPending ? "Creating…" : "Create upload"}
          </button>
        </form>
      </Panel>

      <Panel
        title="Upload Result"
        action={result && <button className="btn btn-ghost btn-sm" onClick={() => refresh.mutate(result.upload_id)} disabled={refresh.isPending}>
          <RefreshCw size={13} /> Refresh
        </button>}
      >
        {!result ? <div className="empty-copy">The KEK-wrapped payload will appear here after creation.</div> : (
          <div className="compact-stack">
            <KVList items={[
              ["Upload ID", result.upload_id],
              ["Status", <StatusPill status={result.status} />],
              ["Target", result.target_id],
              ["Sequence", result.sequence],
              ["KEK", `${result.kek_id} · v${result.kek_version}`],
              ["Data Key", `${result.data_key_id} · v${result.data_key_version}`],
              ["Wrap Suite", result.wrap_suite_id],
            ]} />
            <MonoReadout label="Nonce (base64)" value={result.nonce} copyable />
            <MonoReadout label="Wrapped key (base64)" value={result.wrapped_key} copyable />
            <MonoReadout label="Authentication tag (base64)" value={result.tag} copyable />
            <MonoReadout label="AAD (base64)" value={result.aad_b64} copyable />
            {result.status === "UPLOAD_PENDING" && (
              <button className="btn btn-primary" onClick={() => confirm.mutate(result.upload_id)} disabled={confirm.isPending}>
                <CheckCircle2 size={15} /> {confirm.isPending ? "Confirming…" : "Confirm device receipt"}
              </button>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}

function DownloadView({ keys, defaultPolicyID }: { keys: KeyDTO[]; defaultPolicyID: string }) {
  const qc = useQueryClient();
  const [downloadID, setDownloadID] = useState(newDownloadID);
  const [targetID, setTargetID] = useState("");
  const [sequence, setSequence] = useState("1");
  const [kekID, setKEKID] = useState("");
  const [kekVersion, setKEKVersion] = useState("");
  const [dataKeyID, setDataKeyID] = useState("");
  const [dataKeyVersion, setDataKeyVersion] = useState("1");
  const [name, setName] = useState("");
  const [policyID, setPolicyID] = useState(defaultPolicyID);
  const [nonce, setNonce] = useState("");
  const [wrappedKey, setWrappedKey] = useState("");
  const [tag, setTag] = useState("");
  const [aadB64, setAADB64] = useState("");
  const [result, setResult] = useState<KeyDownloadDTO | null>(null);

  const keks = keys.filter((key) => key.purpose === "key_wrap" && key.status === "ACTIVE" &&
    (key.suite_id === "AES_256_GCM" || key.suite_id === "SM4_GCM"));
  const existingDataKey = keys.find((key) => key.key_id === dataKeyID);
  const selectedKEK = keks.find((key) => key.key_id === kekID);
  const createsVersion = !!existingDataKey;

  const download = useMutation({
    mutationFn: (req: ImportKeyDownloadReq) => api.post<KeyDownloadDTO>(apiPaths.keyDownloads, req),
    onSuccess: (value) => {
      setResult(value);
      qc.invalidateQueries({ queryKey: ["keys"] });
      showToast("downloaded key imported", "success");
    },
    onError: (error: Error) => showToast(error.message, "error"),
  });
  const refresh = useMutation({
    mutationFn: (id: string) => api.get<KeyDownloadDTO>(apiPaths.keyDownload(id)),
    onSuccess: setResult,
    onError: (error: Error) => showToast(error.message, "error"),
  });

  const resolvedVersion = Number(dataKeyVersion);
  const generateAAD = () => {
    const seq = Number(sequence);
    const version = Number(kekVersion);
    if (!downloadID.trim() || !targetID.trim() || !Number.isSafeInteger(seq) || seq < 1 ||
      !kekID || !Number.isSafeInteger(version) || version < 1 || !dataKeyID.trim() ||
      !Number.isSafeInteger(resolvedVersion) || resolvedVersion < 1 || !selectedKEK) {
      showToast("complete the transfer metadata before generating AAD", "error");
      return;
    }
    const canonical = JSON.stringify({
      format_version: 1,
      download_id: downloadID.trim(),
      target_id: targetID.trim(),
      sequence: seq,
      kek_id: kekID,
      kek_version: version,
      data_key_id: dataKeyID.trim(),
      data_key_version: resolvedVersion,
      data_suite_id: "SM4_GCM",
      wrap_suite_id: selectedKEK.suite_id,
    });
    setAADB64(toBase64(canonical));
    showToast("canonical AAD generated", "info");
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const seq = Number(sequence);
    const version = Number(kekVersion);
    if (!downloadID.trim() || !targetID.trim() || !kekID || !dataKeyID.trim() ||
      !Number.isSafeInteger(seq) || seq < 1 || !Number.isSafeInteger(version) || version < 1 ||
      !Number.isSafeInteger(resolvedVersion) || resolvedVersion < 1 || !nonce || !wrappedKey || !tag || !aadB64) {
      showToast("complete all required metadata and encrypted payload fields", "error");
      return;
    }
    if (!createsVersion && (!name.trim() || !(policyID || defaultPolicyID))) {
      showToast("a new Key ID requires a name and policy", "error");
      return;
    }
    download.mutate({
      download_id: downloadID.trim(),
      target_id: targetID.trim(),
      sequence: seq,
      kek_id: kekID,
      kek_version: version,
      data_key_id: dataKeyID.trim(),
      data_key_version: resolvedVersion,
      data_suite_id: "SM4_GCM",
      name: createsVersion ? undefined : name.trim(),
      policy_id: createsVersion ? undefined : (policyID || defaultPolicyID),
      nonce: nonce.trim(),
      wrapped_key: wrappedKey.trim(),
      tag: tag.trim(),
      aad_b64: aadB64.trim(),
    });
  };

  return (
    <div className="grid-2 page-section">
      <Panel title="Import Key Download">
        <form className="compact-stack" onSubmit={submit}>
          <div className="form-grid">
            <Field label="Download ID">
              <input className="input" value={downloadID} onChange={(event) => setDownloadID(event.target.value)} />
            </Field>
            <Field label="Device target">
              <input className="input" value={targetID} onChange={(event) => setTargetID(event.target.value)} placeholder="crypto-device-01" />
            </Field>
            <Field label="Replay sequence">
              <input className="input" type="number" min="1" value={sequence} onChange={(event) => setSequence(event.target.value)} />
            </Field>
            <Field label="KEK">
              <select className="select" value={kekID} onChange={(event) => {
                setKEKID(event.target.value);
                const selected = keks.find((key) => key.key_id === event.target.value);
                setKEKVersion(selected ? String(selected.current_version) : "");
              }}>
                <option value="">Select the device KEK</option>
                {keks.map((key) => <option key={key.key_id} value={key.key_id}>{key.name} · {key.suite_id}</option>)}
              </select>
            </Field>
            <Field label="KEK version">
              <input className="input" type="number" min="1" value={kekVersion} onChange={(event) => setKEKVersion(event.target.value)} />
            </Field>
            <Field label="Data Key ID">
              <input className="input" list="download-data-keys" value={dataKeyID} onChange={(event) => {
                const next = event.target.value;
                setDataKeyID(next);
                const existing = keys.find((key) => key.key_id === next);
                setDataKeyVersion(existing ? String(existing.current_version + 1) : "1");
              }} placeholder="new or existing Key ID" />
              <datalist id="download-data-keys">
                {keys.filter((key) => key.purpose === "encrypt_decrypt" && key.suite_id === "SM4_GCM").map((key) =>
                  <option key={key.key_id} value={key.key_id}>{key.name}</option>)}
              </datalist>
            </Field>
            <Field label="Data key version">
              <input className="input" type="number" min="1" value={dataKeyVersion} onChange={(event) => setDataKeyVersion(event.target.value)} />
            </Field>
            <Field label="Import operation">
              <div className="input input-static"><strong>{createsVersion ? "Create next version" : "Create new key"}</strong><span>SM4_GCM</span></div>
            </Field>
          </div>

          {!createsVersion && (
            <div className="form-grid">
              <Field label="New key name">
                <input className="input" value={name} onChange={(event) => setName(event.target.value)} placeholder="Downloaded data key" />
              </Field>
              <Field label="Policy ID">
                <input className="input" value={policyID} onChange={(event) => setPolicyID(event.target.value)} placeholder={defaultPolicyID || "default-v1"} />
              </Field>
            </div>
          )}

          <div className="transfer-divider">KEK-wrapped payload</div>
          <div className="form-grid">
            <Field label="Nonce (base64)">
              <textarea className="textarea" value={nonce} onChange={(event) => setNonce(event.target.value)} />
            </Field>
            <Field label="Authentication tag (base64)">
              <textarea className="textarea" value={tag} onChange={(event) => setTag(event.target.value)} />
            </Field>
          </div>
          <Field label="Wrapped key (base64)">
            <textarea className="textarea" value={wrappedKey} onChange={(event) => setWrappedKey(event.target.value)} />
          </Field>
          <Field label="AAD (base64)">
            <textarea className="textarea" value={aadB64} onChange={(event) => setAADB64(event.target.value)} />
          </Field>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button className="btn btn-secondary" type="button" onClick={generateAAD}>Generate canonical AAD</button>
            <button className="btn btn-primary" type="submit" disabled={download.isPending || keks.length === 0}>
              <ArrowDownToLine size={15} /> {download.isPending ? "Importing…" : "Verify and import"}
            </button>
          </div>
        </form>
      </Panel>

      <Panel
        title="Download Result"
        action={result && <button className="btn btn-ghost btn-sm" onClick={() => refresh.mutate(result.download_id)} disabled={refresh.isPending}>
          <RefreshCw size={13} /> Refresh
        </button>}
      >
        {!result ? <div className="empty-copy">Only imported key metadata is shown. Plaintext key material is never returned.</div> : (
          <div className="compact-stack">
            <KVList items={[
              ["Download ID", result.download_id],
              ["Status", <StatusPill status={result.status} />],
              ["Operation", result.operation === "CREATE_KEY" ? "Created new key" : "Created pending version"],
              ["Target", result.target_id],
              ["Sequence", result.sequence],
              ["KEK", `${result.kek_id} · v${result.kek_version}`],
              ["Data Key", `${result.data_key_id} · v${result.data_key_version}`],
              ["Suite", result.data_suite_id],
              ["Imported", result.imported_at ? new Date(result.imported_at).toLocaleString() : "pending"],
            ]} />
          </div>
        )}
      </Panel>
    </div>
  );
}

export function KeyTransferPage() {
  const [mode, setMode] = useState<TransferMode>("upload");
  const { data, isLoading, error } = useQuery({
    queryKey: ["keys", "key-transfer"],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keys),
  });
  const { data: policy } = useQuery({
    queryKey: ["signed-policy"],
    queryFn: () => api.get<SignedPolicy>(apiPaths.policy.signed),
  });

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Key Transfer</h1>
          <p className="section-subtitle">Move Data Encryption Keys (DEKs) to or from a cryptographic device using its pre-shared Key Encryption Key (KEK).</p>
        </div>
        <div className="transfer-mode" role="tablist" aria-label="Key transfer direction">
          <button className={`btn btn-sm ${mode === "upload" ? "btn-primary" : "btn-secondary"}`} onClick={() => setMode("upload")}>
            <ArrowUpFromLine size={14} /> Key Upload
          </button>
          <button className={`btn btn-sm ${mode === "download" ? "btn-primary" : "btn-secondary"}`} onClick={() => setMode("download")}>
            <ArrowDownToLine size={14} /> Key Download
          </button>
        </div>
      </div>

      {isLoading ? <Loading label="loading eligible keys..." /> :
        error ? <ErrorState message={error.message} /> :
          mode === "upload" ? <UploadView keys={data?.keys ?? []} /> :
            <DownloadView keys={data?.keys ?? []} defaultPolicyID={policy?.policy_id ?? ""} />}
    </PageContainer>
  );
}
