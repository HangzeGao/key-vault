import type React from "react";

export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

/** format a count, showing "-" for negative sentinels (unavailable). */
export function formatCount(n: number | undefined | null): string {
  if (n === undefined || n === null || n < 0) return "-";
  return String(n);
}

export function formatBytes(bytes: number | undefined | null): string {
  if (bytes === undefined || bytes === null || !Number.isFinite(bytes) || bytes < 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unit = units[0];
  for (let i = 1; i < units.length && value >= 1024; i += 1) {
    value /= 1024;
    unit = units[i];
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${unit}`;
}

export function StatusRow({ label, value, ok }: { label: string; value: string | number; ok?: boolean }) {
  const color = ok === undefined ? "var(--text-primary)" : ok ? "var(--success)" : "var(--danger)";
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
      <span style={{ color: "var(--text-tertiary)", fontSize: 12 }}>{label}</span>
      <span style={{ color, fontFamily: '"JetBrains Mono", monospace', fontSize: 12 }}>{value}</span>
    </div>
  );
}

export function SignalPill({ label, tone = "neutral" }: { label: string; tone?: "success" | "warning" | "danger" | "info" | "neutral" }) {
  const color =
    tone === "success" ? "var(--success)" :
    tone === "warning" ? "var(--warning)" :
    tone === "danger" ? "var(--danger)" :
    tone === "info" ? "var(--info)" :
    "var(--text-secondary)";
  const background =
    tone === "success" ? "var(--success-dim)" :
    tone === "warning" ? "var(--warning-dim)" :
    tone === "danger" ? "var(--danger-dim)" :
    tone === "info" ? "var(--info-dim)" :
    "var(--pill-neutral-bg)";
  return (
    <span className="signal-pill" style={{ color, background, borderColor: color }}>
      {label}
    </span>
  );
}

export function StatCard({ icon, label, value, sub }: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub: { label: string; value: string | number; color: string }[];
}) {
  return (
    <div className="stat-card">
      <div className="stat-label" style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ opacity: 0.5 }}>{icon}</span>
        {label}
      </div>
      <div className="stat-value">{value}</div>
      {sub.length > 0 && (
        <div className="stat-sub">
          {sub.map((s) => (
            <span key={s.label} style={{ color: s.color }}>
              {s.value} {s.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function KeyStat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="key-stat">
      <div style={{ fontSize: 24, fontFamily: '"JetBrains Mono", monospace', color, fontWeight: 600 }}>{value}</div>
      <div style={{ fontSize: 11, color: "var(--text-tertiary)", marginTop: 4 }}>{label}</div>
    </div>
  );
}

export function MetricStrip({ items }: { items: Array<{ label: string; value: string | number; tone?: "success" | "warning" | "danger" | "info" | "neutral" }> }) {
  return (
    <div className="metric-strip">
      {items.map((item) => (
        <div key={item.label} className={`metric-strip-item metric-${item.tone ?? "neutral"}`}>
          <div className="metric-strip-value">{item.value}</div>
          <div className="metric-strip-label">{item.label}</div>
        </div>
      ))}
    </div>
  );
}
