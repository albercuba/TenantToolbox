import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Tenant = {
  name: string;
  domain: string;
  status: "Connected" | "Needs attention";
  users: number;
  score: string;
};

const tenants: Tenant[] = [
  { name: "Northwind Traders", domain: "northwind.example", status: "Connected", users: 248, score: "87%" },
  { name: "Contoso Healthcare", domain: "contoso-health.example", status: "Connected", users: 184, score: "74%" },
  { name: "Fabrikam Legal", domain: "fabrikam-legal.example", status: "Needs attention", users: 96, score: "61%" },
];

function Icon({ children }: { children: ReactNode }) {
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">{children}</svg>;
}

function App() {
  const [activeView, setActiveView] = useState("dashboard");
  const [apiStatus, setApiStatus] = useState("Checking API…");
  const [token, setToken] = useState(() => localStorage.getItem("tenanttoolbox_token"));

  useEffect(() => {
    fetch("/api/health")
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then(() => setApiStatus("API healthy"))
      .catch(() => setApiStatus("API unavailable"));
  }, []);

  const navigate = (view: string) => setActiveView(view);

  if (!token) return <Login onLogin={(accessToken) => { localStorage.setItem("tenanttoolbox_token", accessToken); setToken(accessToken); }} />;

  return (
    <>
      <header className="navbar">
        <button className="navbar-menu-btn" aria-label="Toggle menu"><Icon><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" /></Icon></button>
        <div className="navbar-brand"><div className="logo-mark">T</div>TenantToolbox</div>
        <div className="navbar-search"><Icon><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></Icon><input aria-label="Search tenants" placeholder="Search tenants, users, alerts…" /></div>
        <div className="navbar-actions"><button className="navbar-icon-btn" title="Notifications" aria-label="Notifications"><Icon><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></Icon><span className="dot" /></button><div className="navbar-avatar" title="MSP technician">A</div></div>
      </header>

      <aside className="sidebar">
        <button className={`sidebar-item ${activeView === "dashboard" ? "active" : ""}`} onClick={() => navigate("dashboard")}><Icon><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></Icon>Dashboard</button>
        <button className={`sidebar-item ${activeView === "tenants" ? "active" : ""}`} onClick={() => navigate("tenants")}><Icon><path d="M3 21h18M5 21V5l7-3 7 3v16M9 8h1M14 8h1M9 12h1M14 12h1" /></Icon>Client tenants<span className="count">{tenants.length}</span></button>
        <div className="sidebar-section-label">Security</div>
        <button className="sidebar-item"><Icon><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="m9 12 2 2 4-4" /></Icon>Secure Autopilot</button>
        <button className="sidebar-item"><Icon><path d="M4 4h16v16H4z" /><path d="M8 12h8M8 8h5M8 16h6" /></Icon>Alerts</button>
        <button className="sidebar-item"><Icon><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82" /></Icon>Audit log</button>
        <div className="sidebar-section-label">Management</div>
        <button className="sidebar-item"><Icon><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" /></Icon>Users</button>
        <button className="sidebar-item"><Icon><path d="M4 4h16v16H4z" /><path d="M8 8h8v8H8z" /></Icon>Devices</button>
        <button className="sidebar-item"><Icon><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82" /></Icon>Settings</button>
      </aside>

      <main className="main">
        {activeView === "dashboard" ? <Dashboard apiStatus={apiStatus} onTenants={() => navigate("tenants")} /> : <TenantList token={token} />}
      </main>
    </>
  );
}

function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    const response = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: email, password }) });
    if (!response.ok) { setError("Sign-in failed. Check your email and password."); return; }
    onLogin((await response.json()).access_token);
  };

  return <main className="main" style={{ maxWidth: "520px", margin: "80px auto" }}><div className="panel"><div className="page-head"><div><h1 className="page-title">Sign in to TenantToolbox</h1><div className="page-subtitle">Manage your Microsoft 365 client tenants securely</div></div></div><form onSubmit={submit}><label className="form-field"><span>Email</span><input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label><label className="form-field"><span>Password</span><input required type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>{error && <div className="delta down">{error}</div>}<button className="btn btn-primary" type="submit">Sign in</button></form></div></main>;
}

function Dashboard({ apiStatus, onTenants }: { apiStatus: string; onTenants: () => void }) {
  return <div className="view active">
    <div className="page-head"><div><h1 className="page-title">MSP Dashboard</h1><div className="page-subtitle">Security posture across your Microsoft 365 client tenants</div></div><div className="page-actions"><button className="btn" onClick={() => window.location.reload()}>Refresh</button><button className="btn btn-primary" onClick={onTenants}>View tenants</button></div></div>
    <div className="card-grid"><div className="stat-card"><div className="label">Connected tenants</div><div className="value">3</div><div className="delta up">All tenant connections active</div></div><div className="stat-card"><div className="label">Average security score</div><div className="value">74%</div><div className="delta up">▲ 6% this month</div></div><div className="stat-card"><div className="label">Open security alerts</div><div className="value">8</div><div className="delta down">3 high priority</div></div><div className="stat-card"><div className="label">API status</div><div className="value" style={{ fontSize: "18px" }}>{apiStatus}</div><div className="delta flat">Foundation health check</div></div></div>
    <h3 className="section-label">Quick actions</h3><div className="shortcut-grid"><button className="shortcut-card" onClick={onTenants}><div className="icon-wrap" style={{ background: "var(--fp-primary-tint)" }}><Icon><path d="M3 21h18M5 21V5l7-3 7 3v16" /></Icon></div><span className="label">Manage tenants</span></button><button className="shortcut-card"><div className="icon-wrap" style={{ background: "var(--fp-green-tint)" }}><Icon><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /></Icon></div><span className="label">Review security posture</span></button><button className="shortcut-card"><div className="icon-wrap" style={{ background: "var(--fp-orange-tint)" }}><Icon><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.7 2.4 17.4A2 2 0 0 0 4.1 20h15.8a2 2 0 0 0 1.7-2.6L13.7 3.7a2 2 0 0 0-3.4 0Z" /></Icon></div><span className="label">Review alerts</span></button><button className="shortcut-card"><div className="icon-wrap" style={{ background: "var(--fp-grey-tint)" }}><Icon><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" /><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z" /></Icon></div><span className="label">Generate report</span></button></div>
    <div className="two-col"><div className="panel"><div className="panel-head"><h3>Client tenant posture</h3><a href="#tenants" onClick={(event) => { event.preventDefault(); onTenants(); }}>View all</a></div>{tenants.map((tenant) => <div className="mini-row" key={tenant.domain}><div><div className="name">{tenant.name}</div><div className="sub">{tenant.domain}</div></div><span className={`badge ${tenant.status === "Connected" ? "ok" : "warn"}`}><span className="dot" />{tenant.score}</span></div>)}</div><div className="panel"><div className="panel-head"><h3>Recent activity</h3><a href="#audit">View audit log</a></div><div className="mini-row"><div><div className="name">Tenant sync completed</div><div className="sub">Northwind Traders</div></div><span className="sub">12 min ago</span></div><div className="mini-row"><div><div className="name">Baseline drift detected</div><div className="sub">Fabrikam Legal</div></div><span className="sub">38 min ago</span></div><div className="mini-row"><div><div className="name">New tenant connected</div><div className="sub">Contoso Healthcare</div></div><span className="sub">Yesterday</span></div></div></div>
  </div>;
}

function TenantList({ token }: { token: string }) {
  const [connectedTenants, setConnectedTenants] = useState<Tenant[]>([]);

  useEffect(() => {
    fetch("/api/tenants", { headers: { Authorization: `Bearer ${token}` } })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then((items: Array<{ display_name: string; tenant_id: string; connection_status: string }>) => setConnectedTenants(items.map((item) => ({ name: item.display_name, domain: item.tenant_id, status: item.connection_status === "connected" ? "Connected" : "Needs attention", users: 0, score: "—" }))));
  }, [token]);

  const rows = connectedTenants.length ? connectedTenants : tenants;
  return <div className="view active"><div className="breadcrumb"><a href="#dashboard">Home</a><span className="sep">/</span><span>Client tenants</span></div><div className="page-head"><div><h1 className="page-title">Client tenants</h1><div className="page-subtitle">{tenants.length} connected Microsoft 365 organizations</div></div><div className="page-actions"><button className="btn btn-primary">+ Connect tenant</button></div></div><div className="list-table-wrap"><table className="list-table"><thead><tr><th>Tenant</th><th>Domain</th><th>Users</th><th>Security score</th><th>Connection</th></tr></thead><tbody>{rows.map((tenant) => <tr key={tenant.domain}><td className="cell-primary">{tenant.name}</td><td>{tenant.domain}</td><td>{tenant.users}</td><td>{tenant.score}</td><td><span className={`badge ${tenant.status === "Connected" ? "ok" : "warn"}`}><span className="dot" />{tenant.status}</span></td></tr>)}</tbody></table></div></div>;
}

createRoot(document.getElementById("root")!).render(<App />);
