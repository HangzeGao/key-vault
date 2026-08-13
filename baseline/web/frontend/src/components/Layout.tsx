import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  LogOut,
  Sun,
  Moon,
  ShieldCheck,
  Satellite,
  RadioTower,
  Menu,
  X,
} from "lucide-react";
import { useAuth, useTheme } from "../lib/store";

interface NavEntry {
  to: string;
  label: string;
  icon: ReactNode;
}

const missionNav: NavEntry[] = [
  { to: "/ui/dashboard", label: "Operations Overview", icon: <LayoutDashboard /> },
  { to: "/ui/tc-security", label: "TC Uplink", icon: <Satellite /> },
  { to: "/ui/downlink-security", label: "Raw Downlink", icon: <RadioTower /> },
];

const assuranceNav: NavEntry[] = [
  { to: "/ui/system", label: "System & Audit", icon: <ShieldCheck /> },
];

function NavGroup({ label, entries, onNavigate }: { label: string; entries: NavEntry[]; onNavigate?: () => void }) {
  return (
    <div className="nav-group">
      <div className="nav-group-label">{label}</div>
      {entries.map((e) => (
        <NavLink key={e.to} to={e.to} onClick={onNavigate} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
          {e.icon}
          {e.label}
        </NavLink>
      ))}
    </div>
  );
}

export function Sidebar({ mobileOpen = false, onClose }: { mobileOpen?: boolean; onClose?: () => void }) {
  const { token, tenantId, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  return (
    <aside className={`sidebar ${mobileOpen ? "mobile-open" : ""}`}>
      <button className="sidebar-close" type="button" onClick={onClose} aria-label="Close navigation">
        <X size={18} />
      </button>
      <div className="brand">
        <div className="brand-title">CCSDS</div>
        <div className="brand-sub">mission security</div>
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        <NavGroup label="Mission Operations" entries={missionNav} onNavigate={onClose} />
        <NavGroup label="Assurance" entries={assuranceNav} onNavigate={onClose} />
      </div>
      <div style={{ padding: "12px 18px", borderTop: "1px solid var(--border)", fontSize: 11, fontFamily: '"JetBrains Mono", monospace', color: "var(--text-tertiary)" }}>
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

export function Topbar({ children, onOpenMenu }: { children?: ReactNode; onOpenMenu?: () => void }) {
  const location = useLocation();
  const path = location.pathname.replace("/ui/", "").replace("/ui", "");
  return (
    <div className="topbar">
      <button className="mobile-menu-button" type="button" onClick={onOpenMenu} aria-label="Open navigation">
        <Menu size={18} />
      </button>
      <div className="breadcrumb">
        <span>ccsds</span>
        <span>/</span>
        <span style={{ color: "var(--accent)" }}>{path || "dashboard"}</span>
      </div>
      <div style={{ flex: 1 }} />
      {children}
    </div>
  );
}

export function PageContainer({ children }: { children: ReactNode }) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  return (
    <div className="app-shell">
      <Sidebar mobileOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />
      {mobileNavOpen && <button className="sidebar-scrim" type="button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}
      <div className="main-area">
        <Topbar onOpenMenu={() => setMobileNavOpen(true)} />
        <div className="content stagger">{children}</div>
      </div>
    </div>
  );
}
