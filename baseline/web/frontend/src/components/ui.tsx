import { useEffect, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";

export function HashValue({ value, label = "hash" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const shortened = value.length > 28 ? `${value.slice(0, 12)}...${value.slice(-8)}` : value;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      showToast("copy failed; select text manually", "error");
    }
  };
  if (!value) return <span className="hash-value hash-value-empty">--</span>;
  return <button type="button" className="hash-value" onClick={copy} title={`Copy full ${label}: ${value}`} aria-label={`Copy full ${label}`}><span>{shortened}</span>{copied ? <Check size={11} /> : <Copy size={11} />}</button>;
}

export function Panel({ title, action, children, bodyClass }: { title?: string; action?: ReactNode; children: ReactNode; bodyClass?: string }) {
  return <div className="panel">{title && <div className="panel-header"><span className="panel-title">{title}</span>{action}</div>}<div className={`panel-body ${bodyClass ?? ""}`}>{children}</div></div>;
}

export function EmptyState({ icon, message }: { icon: ReactNode; message: string }) {
  return <div className="empty-state">{icon}<div>{message}</div></div>;
}

export function Loading({ label }: { label?: string }) {
  return <div className="loading-state"><div className="spinner" />{label && <span>{label}</span>}</div>;
}

export function ErrorState({ message }: { message: string }) {
  return <div className="error-state">{message}</div>;
}

export function showToast(message: string, type: "success" | "error" | "info" | "warning" = "info") {
  window.dispatchEvent(new CustomEvent("kvlt-toast", { detail: { message, type } }));
}

export function ToastContainer() {
  const [toasts, setToasts] = useState<{ id: number; message: string; type: string }[]>([]);
  useEffect(() => {
    const listener = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      const id = Date.now() + Math.random();
      setToasts((previous) => [...previous, { id, ...detail }]);
      setTimeout(() => setToasts((previous) => previous.filter((toast) => toast.id !== id)), 3500);
    };
    window.addEventListener("kvlt-toast", listener);
    return () => window.removeEventListener("kvlt-toast", listener);
  }, []);
  return <div className="toast-container">{toasts.map((toast) => <div key={toast.id} className={`toast toast-${toast.type === "warning" ? "error" : toast.type}`}>{toast.message}</div>)}</div>;
}
