import { useState, type ReactNode } from "react";
import { Copy, Check } from "lucide-react";

// Status → pill class mapping.
export function statusPillClass(status: string): string {
  switch (status) {
    case "ACTIVE":
    case "READY":
      return "pill pill-success";
    case "DISABLED":
    case "DEGRADED":
    case "DESTROY_PENDING":
    case "EXPIRED":
      return "pill pill-warning";
    case "DESTROYED":
    case "REVOKED":
      return "pill pill-danger";
    case "PRE_ACTIVE":
    case "REGISTERED":
      return "pill pill-info";
    default:
      return "pill pill-neutral";
  }
}

export function StatusPill({ status }: { status: string }) {
  return <span className={statusPillClass(status)}>{status}</span>;
}

export function SuiteBadge({ suite }: { suite: string }) {
  return <span className="suite-badge">{suite}</span>;
}

export function MonoReadout({
  value,
  label,
  copyable = false,
}: {
  value: string;
  label?: string;
  copyable?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    // Try Clipboard API first (requires secure context: HTTPS or localhost).
    // Fall back to execCommand for non-secure contexts (e.g. http://<ip>:8080).
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (!ok) throw new Error("execCommand failed");
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      showToast("copy failed — select text manually", "error");
    }
  };
  return (
    <div>
      {label && <div className="input-label" style={{ marginBottom: 6 }}>{label}</div>}
      <div style={{ position: "relative" }}>
        <div className="mono-readout">
          {value || <span style={{ color: "var(--text-tertiary)" }}>—</span>}
        </div>
        {copyable && value && (
          <button
            type="button"
            onClick={copy}
            className="btn btn-ghost"
            style={{
              position: "absolute",
              top: 6,
              right: 6,
              padding: 4,
              background: "var(--bg-surface-2)",
              border: "1px solid var(--border-bright)",
              borderRadius: 2,
              cursor: "pointer",
              color: "var(--text-secondary)",
              display: "flex",
              zIndex: 10,
            }}
            title="Copy to clipboard"
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
          </button>
        )}
      </div>
    </div>
  );
}

// HashValue keeps dense audit tables readable without making a shortened hash
// look like the complete value. The full API value remains available for copy.
export function HashValue({ value, label = "hash" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const shortened = value.length > 28 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
  const copy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (!ok) throw new Error("execCommand failed");
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      showToast("copy failed — select text manually", "error");
    }
  };
  if (!value) return <span className="hash-value hash-value-empty">—</span>;
  return (
    <button type="button" className="hash-value" onClick={copy} title={`Copy full ${label}: ${value}`} aria-label={`Copy full ${label}`}>
      <span>{shortened}</span>{copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

export function Panel({
  title,
  action,
  children,
  bodyClass,
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  bodyClass?: string;
}) {
  return (
    <div className="panel">
      {title && (
        <div className="panel-header">
          <span className="panel-title">{title}</span>
          {action}
        </div>
      )}
      <div className={`panel-body ${bodyClass ?? ""}`}>{children}</div>
    </div>
  );
}

export function EmptyState({ icon, message }: { icon: ReactNode; message: string }) {
  return (
    <div className="empty-state">
      {icon}
      <div>{message}</div>
    </div>
  );
}

export function Loading({ label }: { label?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: 20, color: "var(--text-tertiary)" }}>
      <div className="spinner" />
      {label && <span style={{ fontSize: 12, fontFamily: '"JetBrains Mono", monospace' }}>{label}</span>}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div
      style={{
        padding: 20,
        color: "var(--danger)",
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 12,
        border: "1px solid var(--danger)",
        background: "var(--danger-dim)",
        borderRadius: 2,
      }}
    >
      {message}
    </div>
  );
}

// Toast system (simple, via custom event).
export function showToast(message: string, type: "success" | "error" | "info" | "warning" = "info") {
  window.dispatchEvent(new CustomEvent("kvlt-toast", { detail: { message, type } }));
}

export function ToastContainer() {
  const [toasts, setToasts] = useState<{ id: number; message: string; type: string }[]>([]);
  useState(() => {
    window.addEventListener("kvlt-toast", (e) => {
      const detail = (e as CustomEvent).detail;
      const id = Date.now() + Math.random();
      setToasts((prev) => [...prev, { id, ...detail }]);
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
    });
  });
  return (
    <div className="toast-container">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast-${t.type === "warning" ? "error" : t.type}`}>
          {t.message}
        </div>
      ))}
    </div>
  );
}

export function Modal({
  title,
  children,
  onClose,
  onConfirm,
  confirmLabel,
  danger,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  onConfirm?: () => void;
  confirmLabel?: string;
  danger?: boolean;
}) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="panel-title">{title}</span>
        </div>
        <div className="modal-body">{children}</div>
        <div className="modal-footer">
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Cancel
          </button>
          {onConfirm && (
            <button className={`btn btn-sm ${danger ? "btn-danger" : "btn-primary"}`} onClick={onConfirm}>
              {confirmLabel ?? "Confirm"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function KVList({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv-list">
      {items.map(([k, v]) => (
        <>
          <dt key={`k-${k}`}>{k}</dt>
          <dd key={`v-${k}`}>{v}</dd>
        </>
      ))}
    </dl>
  );
}
