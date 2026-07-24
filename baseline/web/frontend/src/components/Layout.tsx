import { type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  KeyRound,
  Lock,
  Shield,
  ScrollText,
  LogOut,
  Layers,
  Boxes,
  Package,
  Settings2,
  Sun,
  Moon,
  Database,
} from "lucide-react";
import { useAuth, useTheme, useUI } from "../lib/store";

interface NavEntry {
  to: string;
  label: string;
  icon: ReactNode;
}

const managementNav: NavEntry[] = [
  { to: "/ui/keys", label: "Key Management", icon: <KeyRound /> },
  { to: "/ui/policy", label: "Policy", icon: <Shield /> },
  { to: "/ui/envelope-config", label: "Envelope Config", icon: <Package /> },
];

const dataNav: NavEntry[] = [
  { to: "/ui/crypto", label: "Crypto Sandbox", icon: <Lock /> },
  { to: "/ui/batch-crypto", label: "Batch Crypto", icon: <Boxes /> },
];

const auditNav: NavEntry[] = [
  { to: "/ui/audit", label: "Audit Log", icon: <ScrollText /> },
  { to: "/ui/lifecycle", label: "Lifecycle", icon: <Layers /> },
];

const opsNav: NavEntry[] = [
  { to: "/ui/dashboard", label: "Dashboard", icon: <LayoutDashboard /> },
  { to: "/ui/database", label: "Database", icon: <Database /> },
];

const simpleNav: NavEntry[] = [
  { to: "/ui/dashboard", label: "Dashboard", icon: <LayoutDashboard /> },
  { to: "/ui/keys", label: "Keys", icon: <KeyRound /> },
  { to: "/ui/crypto", label: "Encrypt / Decrypt", icon: <Lock /> },
];

function NavGroup({ label, entries }: { label: string; entries: NavEntry[] }) {
  return (
    <div className="nav-group">
      <div className="nav-group-label">{label}</div>
      {entries.map((e) => (
        <NavLink key={e.to} to={e.to} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
          {e.icon}
          {e.label}
        </NavLink>
      ))}
    </div>
  );
}

export function Sidebar() {
  const { token, tenantId, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { navigationMode, setNavigationMode } = useUI();
  const advanced = navigationMode === "advanced";
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-title">kvlt</div>
        <div className="brand-sub">engineering baseline</div>
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        {advanced ? <>
          <NavGroup label="Ops Plane" entries={opsNav} />
          <NavGroup label="Management Plane" entries={managementNav} />
          <NavGroup label="Data Plane" entries={dataNav} />
          <NavGroup label="Audit Plane" entries={auditNav} />
        </> : <NavGroup label="Daily workflow" entries={simpleNav} />}
      </div>
      <div style={{ padding: "12px 18px", borderTop: "1px solid var(--border)", fontSize: 11, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)" }}>
        <button className="navigation-mode-button" onClick={() => setNavigationMode(advanced ? "simple" : "advanced")}>
          <Settings2 size={13} /> {advanced ? "Simple mode" : "Advanced controls"}
        </button>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span>{tenantId}</span>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <button
              onClick={toggleTheme}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              style={{
                background: "none",
                border: "none",
                color: "var(--text-tertiary)",
                cursor: "pointer",
                display: "flex",
                padding: 2,
              }}
            >
              {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
            </button>
            {token && (
              <button onClick={logout} title="Logout" style={{ background: "none", border: "none", color: "var(--text-tertiary)", cursor: "pointer", display: "flex", padding: 2 }}>
                <LogOut size={13} />
              </button>
            )}
          </div>
        </div>
        <div style={{ marginTop: 4, color: "var(--success)", fontSize: 9 }}>authenticated</div>
      </div>
    </aside>
  );
}

export function Topbar({ children }: { children?: ReactNode }) {
  const location = useLocation();
  const path = location.pathname.replace("/ui/", "").replace("/ui", "");
  return (
    <div className="topbar">
      <div className="breadcrumb">
        <span>kvlt</span>
        <span>/</span>
        <span style={{ color: "var(--accent)" }}>{path || "dashboard"}</span>
      </div>
      <div style={{ flex: 1 }} />
      {children}
    </div>
  );
}

export function PageContainer({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-area">
        <Topbar />
        <div className="content stagger">{children}</div>
      </div>
    </div>
  );
}
