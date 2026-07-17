import type { HealthResponse, HealthCheck } from "./queries";

const CHECK_ORDER = ["tpm", "resolver", "db", "worker", "audit", "policy"] as const;
const CHECK_LABELS: Record<string, string> = {
  tpm: "TPM",
  resolver: "RESOLVER",
  db: "DB",
  worker: "WORKER",
  audit: "AUDIT",
  policy: "POLICY",
};

const STATUS_DEFINITIONS = [
  { status: "OK", copy: "service is operating within its configured baseline", color: "var(--success)" },
  { status: "WARN", copy: "available, but below the production security or durability baseline", color: "var(--warning)" },
  { status: "DEGRADED", copy: "unavailable or integrity validation failed; operator action is required", color: "var(--danger)" },
];

const DETAIL_LABELS: Record<string, string> = {
  provider: "Provider", runtime_state: "Runtime state", security_boundary: "Security boundary", status_reason: "Status reason", pcrs: "PCR set", transport: "Transport",
  crk_cached: "CRK cached", crk_version: "CRK version", lease_scope: "Lease scope",
  driver: "Driver", durability: "Durability", connection: "Connection",
  failed_jobs: "Failed jobs", poll_interval: "Poll interval", lease_ttl: "Lease TTL", max_attempts: "Max attempts",
  chains: "Chains", verification: "Verification",
  loaded: "Loaded", policy_id: "Policy ID", version: "Version", default_suite: "Default suite", status: "Status", trusted_signing_keys: "Trusted signing keys",
};

function statusColor(status: string): string {
  if (status === "ok") return "var(--success)";
  if (status === "warn") return "var(--warning)";
  return "var(--danger)";
}

interface Props {
  health: HealthResponse | undefined;
  isLoading: boolean;
  error: Error | null;
  highlighted: string | null;
  onHighlight: (check: string | null) => void;
}

export function HealthGrid({ health, isLoading, error, highlighted, onHighlight }: Props) {
  if (isLoading && !health) {
    return <div className="loading-text">loading health...</div>;
  }
  if (error && !health) {
    return (
      <div style={{ padding: 16, background: "var(--bg-inset)", border: "1px solid var(--danger)", borderRadius: 6, color: "var(--danger)", fontSize: 12 }}>
        <strong>ops health unavailable</strong>
        <div className="mono" style={{ fontSize: 11, marginTop: 4, color: "var(--text-tertiary)" }}>
          {error.message}
        </div>
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-tertiary)" }}>
          ops plane requires a token with <code style={{ color: "var(--accent)" }}>ops:read</code> scope.
        </div>
      </div>
    );
  }
  if (!health) return null;

  return (
    <>
      <div className="health-status-legend" aria-label="Health status definitions">
        {STATUS_DEFINITIONS.map((definition) => <span key={definition.status}><i style={{ background: definition.color }} /> <strong>{definition.status}</strong> — {definition.copy}</span>)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8 }}>
        {CHECK_ORDER.map((key) => {
        const check: HealthCheck | undefined = health.checks[key];
        const color = check ? statusColor(check.status) : "var(--danger)";
        const isHighlighted = highlighted === key;
        return (
          <div
            key={key}
            onClick={() => onHighlight(isHighlighted ? null : key)}
            style={{
              background: "linear-gradient(135deg, var(--bg-stat-start), var(--bg-stat-end))",
              border: `1px solid ${isHighlighted ? color : "var(--border)"}`,
              borderRadius: 6,
              padding: 10,
              cursor: "pointer",
              opacity: highlighted && !isHighlighted ? 0.5 : 1,
              transition: "opacity 0.2s, border-color 0.2s",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: color,
                  boxShadow: `0 0 8px ${color}`,
                }}
              />
              <span style={{ color, fontSize: 11, fontWeight: 700, letterSpacing: 0.5 }}>
                {CHECK_LABELS[key]}
              </span>
            </div>
            <div className="mono" style={{ color: "var(--text-tertiary)", fontSize: 10 }}>
              {check?.summary ?? "unknown"}
            </div>
            {check?.error && (
              <div className="mono" style={{ color: "var(--danger)", fontSize: 9, marginTop: 2 }}>
                {check.error}
              </div>
            )}
            {isHighlighted && check?.detail && (
              <div className="health-check-detail">
                {Object.entries(check.detail).map(([name, value]) => <div key={name}><span>{DETAIL_LABELS[name] ?? name.replaceAll("_", " ")}</span><strong>{Array.isArray(value) ? value.join(", ") || "none" : String(value)}</strong></div>)}
              </div>
            )}
          </div>
        );
        })}
      </div>
    </>
  );
}
