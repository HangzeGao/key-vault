const BFF = "/ui/api/v1" as const;

const query = (path: string, params: Record<string, string | number | boolean | undefined>) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") search.set(key, String(value));
  });
  const suffix = search.toString();
  return suffix ? `${path}?${suffix}` : path;
};

export const apiPaths = {
  status: `${BFF}/status`,
  keys: `${BFF}/keys`,
  keysList: (params: Record<string, string | number | boolean | undefined> = {}) => query(`${BFF}/keys`, params),
  key: (id: string) => `${BFF}/keys/${encodeURIComponent(id)}`,
  keyAction: (id: string, action: "enable" | "disable" | "cancel-destroy" | "archive") =>
    `${BFF}/keys/${encodeURIComponent(id)}/${action}`,
  importKey: `${BFF}/keys:import`,
  importKeysBatch: `${BFF}/keys:import-batch`,
  keyUploads: `${BFF}/key-uploads`,
  keyUpload: (id: string) => `${BFF}/key-uploads/${encodeURIComponent(id)}`,
  confirmKeyUpload: (id: string) => `${BFF}/key-uploads/${encodeURIComponent(id)}/confirm`,
  keyDownloads: `${BFF}/key-downloads`,
  keyDownload: (id: string) => `${BFF}/key-downloads/${encodeURIComponent(id)}`,
  crypto: {
    encrypt: `${BFF}/crypto/encrypt`, decrypt: `${BFF}/crypto/decrypt`, convert: `${BFF}/crypto/envelopes:convert`, inspect: `${BFF}/crypto/envelopes:inspect`,
    encryptBatch: `${BFF}/crypto/encrypt-batch`, decryptBatch: `${BFF}/crypto/decrypt-batch`,
  },
  envelopeFormats: `${BFF}/envelope/formats`,
  tenantEnvelopeConfig: (tenantID: string) => `${BFF}/tenants/${encodeURIComponent(tenantID)}/envelope-config`,
  audit: {
    events: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/audit/events`, params),
    heads: `${BFF}/audit/chain/heads`, verify: (chain?: string) => query(`${BFF}/audit/chain/verify`, { chain }),
  },
  lifecycle: {
    jobs: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/lifecycle/jobs`, params),
    outbox: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/lifecycle/outbox`, params),
    config: `${BFF}/lifecycle/config`,
  },
  policy: { signed: `${BFF}/policies/signed`, reload: `${BFF}/policies:reload` },
  ops: {
    health: `${BFF}/ops/health`, dbStatus: `${BFF}/ops/db/status`, resolverRefresh: `${BFF}/ops/resolver:refresh`,
    crkEnvelope: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/ops/crk/envelope`, params),
    repairCRK: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/ops/crk/envelope:repair-aad-digest`, params),
    retryJob: (id: string) => `${BFF}/ops/lifecycle/jobs/${encodeURIComponent(id)}/retry`,
    replayOutbox: (id: string) => `${BFF}/ops/outbox/${encodeURIComponent(id)}/replay`,
  },
} as const;

export type OpsActionRequest = { reason: string; ticket_id: string; impact_scope?: string; operator_confirmation?: boolean };

export const newIdempotencyKey = () =>
  globalThis.crypto?.randomUUID?.() ?? `ops-${Date.now()}-${Math.random().toString(16).slice(2)}`;

export function collectOpsAction(defaultReason: string): { body: OpsActionRequest; headers: Record<string, string> } | null {
  const reason = window.prompt("Operational reason (required)", defaultReason)?.trim();
  if (!reason) return null;
  const ticket = window.prompt("Change/incident ticket ID (required)")?.trim();
  if (!ticket) return null;
  return { body: { reason, ticket_id: ticket }, headers: { "Idempotency-Key": newIdempotencyKey() } };
}
