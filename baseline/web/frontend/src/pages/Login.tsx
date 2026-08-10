import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Lock, ArrowRight, Sun, Moon } from "lucide-react";
import { useAuth, useTheme } from "../lib/store";
import { api, HttpError } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";

export function LoginPage() {
  const { setToken, setTenantId, logout, token } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [input, setInput] = useState(token ?? "");
  const [tenant, setTenant] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) {
      setError("token required");
      return;
    }
    setError("");
    setSubmitting(true);
    setToken(input.trim());
    setTenantId(tenant.trim() || "t-default");
    try {
      await api.get(apiPaths.ops.ccsdsStatus);
      navigate("/ui/dashboard");
    } catch (cause) {
      logout();
      if (cause instanceof HttpError && (cause.status === 401 || cause.status === 403)) {
        setError("authentication failed or console access is not permitted");
      } else {
        setError("operations service unavailable; try again after connectivity is restored");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        position: "relative",
      }}
    >
      {/* Theme toggle */}
      <button
        onClick={toggleTheme}
        title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        style={{
          position: "absolute",
          top: 20,
          right: 24,
          background: "none",
          border: "1px solid var(--border)",
          color: "var(--text-tertiary)",
          cursor: "pointer",
          padding: 6,
          borderRadius: 3,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
      </button>

      {/* Ice signal line */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 1,
          background:
            "linear-gradient(90deg, transparent, var(--accent) 30%, var(--accent-bright) 50%, var(--accent) 70%, transparent)",
          boxShadow: "0 0 12px var(--accent-glow)",
        }}
      />
      <div style={{ width: 380 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div
            className="font-display"
            style={{ fontSize: 40, fontWeight: 800, color: "var(--accent-bright)", lineHeight: 1, textShadow: "0 0 28px var(--accent-glow)" }}
          >
            CCSDS
          </div>
          <div
            style={{
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: 10,
              color: "var(--text-tertiary)",
              letterSpacing: "0.3em",
              textTransform: "uppercase",
              marginTop: 10,
            }}
          >
            mission security / ground console
          </div>
        </div>
        <form onSubmit={submit}>
          <div style={{ marginBottom: 16 }}>
            <label className="input-label">Access Token</label>
            <div style={{ position: "relative" }}>
              <Lock
                size={14}
                style={{
                  position: "absolute",
                  left: 12,
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "var(--text-tertiary)",
                }}
              />
              <input
                className="input"
                type="password"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="enter bearer token"
                style={{ paddingLeft: 34 }}
                autoFocus
              />
            </div>
          </div>
          <div style={{ marginBottom: 20 }}>
            <label className="input-label">Mission / Tenant ID</label>
            <input
              className="input"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              placeholder="t-default"
            />
          </div>
          {error && (
            <div
              style={{
                color: "var(--danger)",
                fontSize: 12,
                fontFamily: '"JetBrains Mono", monospace',
                marginBottom: 12,
              }}
            >
              {error}
            </div>
          )}
          <button type="submit" className="btn btn-primary" style={{ width: "100%" }} disabled={submitting}>
            {submitting ? "Authenticating..." : "Authenticate"}
            <ArrowRight size={14} />
          </button>
        </form>
        <div
          style={{
            marginTop: 24,
            textAlign: "center",
            fontSize: 10,
            fontFamily: '"JetBrains Mono", monospace',
            color: "var(--text-tertiary)",
            lineHeight: 1.8,
          }}
        >
          authenticated control-plane access
        </div>
      </div>
    </div>
  );
}
