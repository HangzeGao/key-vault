import { useEffect, useMemo, useState } from "react";
import { FileCode2, RefreshCw } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths } from "../../lib/apiPaths";
import { useAuth } from "../../lib/store";
import { Panel, MonoReadout, showToast } from "../index";

interface Props { formatOptions: string[]; }
type EnvelopeSummary = { format: string; version: number; flags: number; suite_id: string; key_id: string; key_version: number; policy_version: number; nonce_bytes: number; tag_bytes: number; ciphertext_bytes: number; aad_hash?: string };
const fields = (env: EnvelopeSummary) => [["Version", env.version], ["Flags", env.flags], ["Suite", env.suite_id], ["Key ID", env.key_id], ["Key version", env.key_version], ["Policy version", env.policy_version], ...(env.aad_hash ? [["AAD hash", env.aad_hash]] : [])];
const fallbackFormats = ["json-v1", "configurable-json-v1"];
const nextTarget = (current: string, options: string[]) => options.find((format) => format !== current) ?? current;
const parseEnvelopeInput = (input: string) => {
  const envelope = JSON.parse(input);
  if (!envelope || Array.isArray(envelope) || typeof envelope !== "object") throw new Error("envelope must be a JSON object");
  return envelope;
};

export function EnvelopeInspector({ formatOptions }: Props) {
  const { tenantId } = useAuth();
  const [input, setInput] = useState("");
  const [parsed, setParsed] = useState<EnvelopeSummary | null>(null);
  const [sourceFormat, setSourceFormat] = useState("");
  const targetOptions = useMemo(() => formatOptions.length > 0 ? formatOptions : fallbackFormats, [formatOptions]);
  const [targetFormat, setTargetFormat] = useState(targetOptions[0]);
  const [output, setOutput] = useState("");
  useEffect(() => {
    setTargetFormat((current) => targetOptions.includes(current) ? current : targetOptions[0]);
  }, [targetOptions]);
  const parse = async () => {
    try { const env = await api.post<EnvelopeSummary>(apiPaths.crypto.inspect, { tenant_id: tenantId, envelope: parseEnvelopeInput(input), source_format: sourceFormat || undefined }); setParsed(env); setTargetFormat(nextTarget(env.format, targetOptions)); setOutput(""); }
    catch (error) { setParsed(null); showToast(`inspect failed: ${(error as Error).message}`, "error"); }
  };
  const convert = async () => {
    try {
      const result = await api.post<{ envelope: Record<string, unknown>; envelope_format: string }>(apiPaths.crypto.convert, { tenant_id: tenantId, envelope: parseEnvelopeInput(input), source_format: sourceFormat || undefined, target_format: targetFormat });
      setOutput(JSON.stringify(result.envelope, null, 2)); showToast(`converted to ${result.envelope_format}`, "success");
    } catch (error) { showToast(`conversion failed: ${(error as Error).message}`, "error"); }
  };
  return <Panel title="Envelope Inspector" action={parsed && <span className="mono" style={{ fontSize: 11, color: "var(--accent)" }}>format: {parsed.format}</span>}>
    <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
      <input className="input" value={input} onChange={(e) => setInput(e.target.value)} placeholder="paste envelope JSON..." />
      <select className="select" style={{ width: 180 }} value={sourceFormat} onChange={(e) => setSourceFormat(e.target.value)}><option value="">auto detect</option>{formatOptions.map((value) => <option key={value} value={value}>{value}</option>)}</select>
      <button className="btn btn-secondary" onClick={parse} disabled={!input.trim()}><FileCode2 size={14} /> Parse</button>
    </div>
    {parsed && <div>
      <div className="kv-list" style={{ marginBottom: 14 }}>{fields(parsed).map(([label, value]) => <div key={String(label)}><span>{label}</span><strong className="mono">{String(value)}</strong></div>)}</div>
      <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginBottom: 10 }}>Core envelope fields are read-only. Conversion is performed and audited by the server; no authenticated field can be changed here.</div>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}><span className="mono" style={{ fontSize: 11 }}>convert to:</span><select className="select" value={targetFormat} onChange={(e) => setTargetFormat(e.target.value)}>{targetOptions.map((format) => <option key={format} value={format}>{format}</option>)}</select><button className="btn btn-primary btn-sm" onClick={convert} disabled={!targetFormat || targetFormat === parsed.format}><RefreshCw size={12} /> Convert</button></div>
      {output && <MonoReadout label="Converted envelope JSON" value={output} copyable />}
    </div>}
  </Panel>;
}
