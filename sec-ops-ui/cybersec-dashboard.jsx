import { useState, useRef, useEffect, useCallback } from "react";

const TOOLS = [
  {
    id: "vuln-assess",
    category: "Server",
    icon: "⬡",
    label: "Vulnerability Assessment",
    desc: "CVE scan, open ports, service fingerprinting",
    color: "#e24b4a",
    fields: [{ name: "target", placeholder: "IP or hostname (e.g. 192.168.1.1)", label: "Target" }],
    prompt: (f) => `You are a cybersecurity expert. Perform a simulated vulnerability assessment for: ${f.target}
Return a detailed JSON report ONLY (no markdown, no prose):
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "open_ports": [{"port": N, "service": "...", "version": "...", "risk": "..."}],
  "cves": [{"id": "CVE-...", "severity": "...", "description": "...", "cvss": N}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "password-audit",
    category: "Auth",
    icon: "⬟",
    label: "Password Vulnerability Audit",
    desc: "Hash analysis, brute-force risk, policy compliance",
    color: "#ef9f27",
    fields: [
      { name: "target", placeholder: "System or service URL", label: "Target System" },
      { name: "policy", placeholder: "e.g. 8+ chars, MFA enabled, lockout after 5", label: "Policy Notes" },
    ],
    prompt: (f) => `You are a cybersecurity auditor. Perform a simulated password security audit for: ${f.target}
Policy context: ${f.policy || "none provided"}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "issues": [{"category": "...", "severity": "...", "detail": "..."}],
  "attack_vectors": [{"method": "...", "feasibility": "high|medium|low", "mitigation": "..."}],
  "compliance": {"score": N, "frameworks": [{"name": "...", "status": "pass|fail|partial"}]},
  "recommendations": ["..."]
}`,
  },
  {
    id: "ssl-tls",
    category: "Network",
    icon: "◈",
    label: "SSL/TLS Security Scan",
    desc: "Certificate chain, cipher suites, protocol weaknesses",
    color: "#1d9e75",
    fields: [{ name: "target", placeholder: "Domain or IP (e.g. example.com:443)", label: "Target" }],
    prompt: (f) => `You are an SSL/TLS security expert. Perform a simulated SSL/TLS audit for: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "certificate": {"issuer": "...", "expiry": "...", "key_size": N, "algorithm": "...", "issues": ["..."]},
  "protocols": [{"version": "...", "status": "enabled|disabled", "security": "safe|weak|insecure"}],
  "cipher_suites": [{"name": "...", "strength": "strong|acceptable|weak"}],
  "vulnerabilities": [{"name": "...", "cve": "...", "severity": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "network-recon",
    category: "Network",
    icon: "◇",
    label: "Network Reconnaissance",
    desc: "Topology mapping, host discovery, routing analysis",
    color: "#378add",
    fields: [
      { name: "target", placeholder: "CIDR range or hostname (e.g. 10.0.0.0/24)", label: "Target Range" },
    ],
    prompt: (f) => `You are a network security analyst. Perform a simulated network reconnaissance for: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "high|medium|low",
  "hosts": [{"ip": "...", "hostname": "...", "os": "...", "role": "...", "open_services": ["..."]}],
  "topology": {"segments": N, "gateways": ["..."], "exposed_services": N},
  "risks": [{"type": "...", "description": "...", "severity": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "web-app-scan",
    category: "Application",
    icon: "⬡",
    label: "Web Application Scan",
    desc: "OWASP Top 10, injection, XSS, CSRF, misconfigs",
    color: "#d4537e",
    fields: [
      { name: "target", placeholder: "https://app.example.com", label: "Application URL" },
      { name: "auth", placeholder: "Cookie/token (optional)", label: "Auth Header" },
    ],
    prompt: (f) => `You are a web application penetration tester. Simulate an OWASP Top 10 scan for: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "owasp": [{"id": "A0N:2021", "name": "...", "status": "vulnerable|possible|safe", "detail": "..."}],
  "findings": [{"type": "XSS|SQLi|CSRF|IDOR|...", "severity": "...", "endpoint": "...", "proof_of_concept": "..."}],
  "headers": [{"header": "...", "status": "present|missing", "impact": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "api-security",
    category: "Application",
    icon: "◎",
    label: "API Security Audit",
    desc: "Authentication, rate limiting, data exposure, BOLA",
    color: "#7f77dd",
    fields: [
      { name: "target", placeholder: "https://api.example.com/v1", label: "API Base URL" },
      { name: "spec", placeholder: "Swagger/OpenAPI URL or paste key endpoints", label: "API Spec" },
    ],
    prompt: (f) => `You are an API security specialist. Audit API at: ${f.target}
Spec hints: ${f.spec || "none"}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "auth_issues": [{"issue": "...", "severity": "...", "affected_endpoints": ["..."]}],
  "broken_object_level": [{"endpoint": "...", "finding": "...", "severity": "..."}],
  "rate_limiting": {"status": "enforced|partial|missing", "detail": "..."},
  "data_exposure": [{"endpoint": "...", "exposed_fields": ["..."], "severity": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "dns-analysis",
    category: "Network",
    icon: "◉",
    label: "DNS Security Analysis",
    desc: "DNSSEC, zone transfer, subdomain enumeration",
    color: "#639922",
    fields: [{ name: "target", placeholder: "domain.com", label: "Domain" }],
    prompt: (f) => `You are a DNS security expert. Analyze DNS security for: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "high|medium|low",
  "records": [{"type": "A|MX|TXT|...", "value": "...", "security_notes": "..."}],
  "dnssec": {"enabled": true|false, "issues": ["..."]},
  "zone_transfer": {"status": "allowed|restricted", "risk": "..."},
  "subdomains": [{"name": "...", "ip": "...", "risk": "..."}],
  "email_security": {"spf": "valid|missing|weak", "dkim": "valid|missing", "dmarc": "valid|missing|partial"},
  "recommendations": ["..."]
}`,
  },
  {
    id: "firewall-audit",
    category: "Server",
    icon: "▣",
    label: "Firewall Rules Audit",
    desc: "Rule analysis, overly permissive policies, egress filtering",
    color: "#e24b4a",
    fields: [
      { name: "target", placeholder: "Firewall IP or management endpoint", label: "Target" },
      { name: "rules", placeholder: "Paste firewall rules or describe topology", label: "Rules/Context" },
    ],
    prompt: (f) => `You are a firewall security auditor. Audit firewall at: ${f.target}
Rules/context: ${f.rules || "none"}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "overly_permissive": [{"rule": "...", "risk": "...", "recommendation": "..."}],
  "missing_rules": [{"description": "...", "impact": "..."}],
  "egress_filtering": {"status": "enabled|disabled|partial", "issues": ["..."]},
  "inbound_exposure": [{"service": "...", "port": N, "exposure": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "container-scan",
    category: "Server",
    icon: "⬢",
    label: "Container Security Scan",
    desc: "Image vulnerabilities, privilege escalation, secrets",
    color: "#ef9f27",
    fields: [
      { name: "target", placeholder: "image:tag or registry URL", label: "Image/Registry" },
    ],
    prompt: (f) => `You are a container security expert. Scan container: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "base_image": {"name": "...", "age_days": N, "eol": true|false},
  "cves": [{"id": "CVE-...", "package": "...", "severity": "...", "fixable": true|false}],
  "misconfigs": [{"type": "root_user|exposed_secret|writable_fs|...", "detail": "...", "severity": "..."}],
  "secrets_detected": [{"type": "api_key|password|cert|...", "location": "...", "risk": "..."}],
  "recommendations": ["..."]
}`,
  },
  {
    id: "cloud-posture",
    category: "Server",
    icon: "⬡",
    label: "Cloud Security Posture",
    desc: "IAM review, S3/blob exposure, security groups, logging",
    color: "#378add",
    fields: [
      { name: "target", placeholder: "AWS account ID / Azure sub / GCP project", label: "Cloud Target" },
      { name: "provider", placeholder: "AWS | Azure | GCP", label: "Provider" },
    ],
    prompt: (f) => `You are a cloud security architect. Assess cloud posture for ${f.provider || "cloud"}: ${f.target}
Return ONLY JSON:
{
  "summary": "...",
  "risk_level": "critical|high|medium|low",
  "iam_issues": [{"finding": "...", "severity": "...", "affected": "..."}],
  "public_exposures": [{"resource": "...", "type": "S3|VM|DB|...", "data_risk": "..."}],
  "network_issues": [{"sg_rule": "...", "exposure": "...", "severity": "..."}],
  "logging_gaps": [{"service": "...", "status": "enabled|disabled|partial"}],
  "compliance": [{"framework": "CIS|SOC2|...", "score": N, "critical_gaps": N}],
  "recommendations": ["..."]
}`,
  },
];

const CATEGORY_COLORS = {
  Server: "#e24b4a",
  Auth: "#ef9f27",
  Network: "#378add",
  Application: "#d4537e",
};

function RiskBadge({ level }) {
  const colors = {
    critical: { bg: "#3d1111", text: "#f09595", border: "#792929" },
    high: { bg: "#3d2a0d", text: "#fac775", border: "#7a4e10" },
    medium: { bg: "#1e2e10", text: "#c0dd97", border: "#3a5a1a" },
    low: { bg: "#0d2533", text: "#85b7eb", border: "#1a4a6e" },
  };
  const c = colors[level] || colors.medium;
  return (
    <span style={{
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: "monospace",
    }}>{level}</span>
  );
}

function ResultPanel({ result, loading, toolId }) {
  const [tab, setTab] = useState("overview");

  if (loading) return (
    <div style={{ padding: "2rem", textAlign: "center" }}>
      <div style={{ marginBottom: 12 }}>
        <span style={{ fontFamily: "monospace", fontSize: 13, color: "#5DCAA5", letterSpacing: "0.1em" }}>
          SCANNING
        </span>
        <ScanAnimation />
      </div>
      <p style={{ color: "#888", fontSize: 13 }}>Analyzing target — do not interrupt</p>
    </div>
  );

  if (!result) return (
    <div style={{ padding: "2rem", textAlign: "center", color: "#555" }}>
      <div style={{ fontSize: 32, marginBottom: 8, opacity: 0.3 }}>◎</div>
      <p style={{ fontSize: 13 }}>Configure and run scan to view results</p>
    </div>
  );

  if (result.error) return (
    <div style={{ padding: "1.5rem" }}>
      <div style={{ background: "#2a1111", border: "1px solid #5a2020", borderRadius: 6, padding: "1rem", color: "#f09595", fontSize: 13, fontFamily: "monospace" }}>
        ERROR: {result.error}
      </div>
    </div>
  );

  const tabs = ["overview", "details", "recommendations"];

  return (
    <div>
      <div style={{ display: "flex", gap: 4, padding: "12px 16px 0", borderBottom: "1px solid #2a2a2a" }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            background: tab === t ? "#1a2a1a" : "transparent",
            border: tab === t ? "1px solid #1d9e75" : "1px solid transparent",
            borderRadius: 4, padding: "4px 12px", color: tab === t ? "#5DCAA5" : "#666",
            fontSize: 12, cursor: "pointer", fontFamily: "monospace", textTransform: "uppercase",
            letterSpacing: "0.06em", transition: "all 0.15s",
          }}>{t}</button>
        ))}
        {result.risk_level && <div style={{ marginLeft: "auto", display: "flex", alignItems: "center" }}>
          <RiskBadge level={result.risk_level} />
        </div>}
      </div>

      <div style={{ padding: "1rem 1.25rem", maxHeight: 420, overflowY: "auto" }}>
        {tab === "overview" && <OverviewTab result={result} />}
        {tab === "details" && <DetailsTab result={result} />}
        {tab === "recommendations" && <RecsTab result={result} />}
      </div>
    </div>
  );
}

function OverviewTab({ result }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {result.summary && (
        <div style={{ background: "#111", border: "1px solid #222", borderRadius: 6, padding: "12px 14px" }}>
          <p style={{ color: "#aaa", fontSize: 12, marginBottom: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>Summary</p>
          <p style={{ color: "#e0e0e0", fontSize: 14, lineHeight: 1.6, margin: 0 }}>{result.summary}</p>
        </div>
      )}
      <StatGrid result={result} />
    </div>
  );
}

function StatGrid({ result }) {
  const stats = [];
  if (result.cves?.length != null) stats.push({ label: "CVEs Found", value: result.cves.length, color: result.cves.length > 0 ? "#e24b4a" : "#1d9e75" });
  if (result.open_ports?.length != null) stats.push({ label: "Open Ports", value: result.open_ports.length, color: "#378add" });
  if (result.findings?.length != null) stats.push({ label: "Findings", value: result.findings.length, color: "#ef9f27" });
  if (result.hosts?.length != null) stats.push({ label: "Hosts", value: result.hosts.length, color: "#7f77dd" });
  if (result.issues?.length != null) stats.push({ label: "Issues", value: result.issues.length, color: "#e24b4a" });
  if (result.vulnerabilities?.length != null) stats.push({ label: "Vulnerabilities", value: result.vulnerabilities.length, color: "#e24b4a" });
  if (result.compliance?.score != null) stats.push({ label: "Compliance %", value: result.compliance.score + "%", color: "#1d9e75" });
  if (result.misconfigs?.length != null) stats.push({ label: "Misconfigs", value: result.misconfigs.length, color: "#ef9f27" });

  if (stats.length === 0) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))", gap: 8 }}>
      {stats.map(s => (
        <div key={s.label} style={{ background: "#111", border: "1px solid #222", borderRadius: 6, padding: "10px 12px", textAlign: "center" }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: s.color, fontFamily: "monospace" }}>{s.value}</div>
          <div style={{ fontSize: 11, color: "#666", marginTop: 2, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
        </div>
      ))}
    </div>
  );
}

function DetailsTab({ result }) {
  const sections = [];
  const skip = new Set(["summary", "risk_level", "recommendations"]);

  for (const [key, val] of Object.entries(result)) {
    if (skip.has(key) || val == null) continue;
    sections.push({ key, val });
  }

  if (sections.length === 0) return <p style={{ color: "#555", fontSize: 13 }}>No additional details.</p>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {sections.map(({ key, val }) => (
        <div key={key}>
          <p style={{ color: "#5DCAA5", fontSize: 11, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>{key.replace(/_/g, " ")}</p>
          <DetailValue val={val} />
        </div>
      ))}
    </div>
  );
}

function DetailValue({ val }) {
  if (typeof val === "string" || typeof val === "number" || typeof val === "boolean") {
    return <p style={{ color: "#ccc", fontSize: 13, fontFamily: "monospace" }}>{String(val)}</p>;
  }
  if (Array.isArray(val)) {
    if (val.length === 0) return <p style={{ color: "#555", fontSize: 13 }}>None</p>;
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {val.map((item, i) => (
          <div key={i} style={{ background: "#111", border: "1px solid #1e1e1e", borderRadius: 5, padding: "8px 10px" }}>
            {typeof item === "string" ? (
              <span style={{ color: "#ccc", fontSize: 13, fontFamily: "monospace" }}>{item}</span>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 16px" }}>
                {Object.entries(item).map(([k, v]) => (
                  <span key={k} style={{ fontSize: 12 }}>
                    <span style={{ color: "#666", fontFamily: "monospace" }}>{k}: </span>
                    <span style={{ color: getSeverityColor(k, v), fontFamily: "monospace", fontWeight: 500 }}>{String(v)}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  }
  if (typeof val === "object") {
    return (
      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 16px", background: "#111", border: "1px solid #1e1e1e", borderRadius: 5, padding: "8px 10px" }}>
        {Object.entries(val).map(([k, v]) => (
          <span key={k} style={{ fontSize: 12 }}>
            <span style={{ color: "#666", fontFamily: "monospace" }}>{k}: </span>
            <span style={{ color: getSeverityColor(k, v), fontFamily: "monospace", fontWeight: 500 }}>{Array.isArray(v) ? v.join(", ") : String(v)}</span>
          </span>
        ))}
      </div>
    );
  }
  return null;
}

function getSeverityColor(key, val) {
  const sev = String(val).toLowerCase();
  if (key === "severity" || key === "risk" || key === "risk_level") {
    if (sev === "critical") return "#e24b4a";
    if (sev === "high") return "#ef9f27";
    if (sev === "medium") return "#c0dd97";
    if (sev === "low") return "#85b7eb";
  }
  if (key === "status") {
    if (["missing", "disabled", "allowed", "insecure", "weak", "vulnerable", "fail"].includes(sev)) return "#e24b4a";
    if (["present", "enabled", "valid", "safe", "pass", "enforced"].includes(sev)) return "#5DCAA5";
    if (["partial", "possible"].includes(sev)) return "#ef9f27";
  }
  return "#e0e0e0";
}

function RecsTab({ result }) {
  const recs = result.recommendations || [];
  if (recs.length === 0) return <p style={{ color: "#555", fontSize: 13 }}>No recommendations generated.</p>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {recs.map((r, i) => (
        <div key={i} style={{ display: "flex", gap: 10, background: "#0d1e0d", border: "1px solid #1a3a1a", borderRadius: 6, padding: "10px 12px" }}>
          <span style={{ color: "#5DCAA5", fontFamily: "monospace", fontSize: 13, minWidth: 20 }}>{String(i + 1).padStart(2, "0")}</span>
          <span style={{ color: "#c0dd97", fontSize: 13, lineHeight: 1.5 }}>{r}</span>
        </div>
      ))}
    </div>
  );
}

function ScanAnimation() {
  const [dots, setDots] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setDots(d => (d + 1) % 4), 400);
    return () => clearInterval(t);
  }, []);
  return <span style={{ color: "#5DCAA5", fontFamily: "monospace" }}>{"·".repeat(dots)}</span>;
}

function ToolCard({ tool, onRun }) {
  const [fields, setFields] = useState({});
  const [expanded, setExpanded] = useState(false);

  const handleChange = (name, val) => setFields(f => ({ ...f, [name]: val }));
  const handleRun = () => {
    const filled = tool.fields.every(f => (fields[f.name] || "").trim());
    if (!filled) return;
    onRun(tool, fields);
    setExpanded(false);
  };

  return (
    <div style={{
      background: "#0c0c0c", border: `1px solid ${expanded ? tool.color + "44" : "#1e1e1e"}`,
      borderRadius: 8, overflow: "hidden", transition: "border-color 0.2s",
    }}>
      <button onClick={() => setExpanded(e => !e)} style={{
        width: "100%", background: "transparent", border: "none", cursor: "pointer",
        padding: "14px 16px", display: "flex", alignItems: "center", gap: 12, textAlign: "left",
      }}>
        <span style={{ fontSize: 18, color: tool.color, opacity: 0.8 }}>{tool.icon}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: "#e0e0e0", fontSize: 14, fontWeight: 500, fontFamily: "'JetBrains Mono', monospace" }}>{tool.label}</div>
          <div style={{ color: "#555", fontSize: 12, marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{tool.desc}</div>
        </div>
        <span style={{ color: "#333", fontSize: 10, fontFamily: "monospace" }}>{expanded ? "▲" : "▼"}</span>
      </button>

      {expanded && (
        <div style={{ borderTop: `1px solid #1e1e1e`, padding: "12px 16px 14px" }}>
          {tool.fields.map(f => (
            <div key={f.name} style={{ marginBottom: 10 }}>
              <label style={{ display: "block", color: "#666", fontSize: 11, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{f.label}</label>
              <input
                value={fields[f.name] || ""}
                onChange={e => handleChange(f.name, e.target.value)}
                placeholder={f.placeholder}
                style={{
                  width: "100%", boxSizing: "border-box",
                  background: "#060606", border: "1px solid #2a2a2a", borderRadius: 5,
                  color: "#e0e0e0", padding: "8px 10px", fontSize: 13, fontFamily: "monospace",
                  outline: "none",
                }}
              />
            </div>
          ))}
          <button onClick={handleRun} style={{
            marginTop: 4, background: tool.color + "18", border: `1px solid ${tool.color}55`,
            borderRadius: 5, color: tool.color, padding: "8px 16px", fontSize: 12,
            fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em",
            cursor: "pointer", fontWeight: 600, transition: "all 0.15s",
          }}>▶ Execute Scan</button>
        </div>
      )}
    </div>
  );
}

function Sidebar({ tools, onRun, activeToolId }) {
  const [filter, setFilter] = useState("All");
  const categories = ["All", ...new Set(tools.map(t => t.category))];
  const filtered = filter === "All" ? tools : tools.filter(t => t.category === filter);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0, height: "100%" }}>
      <div style={{ padding: "12px 12px 8px", borderBottom: "1px solid #1a1a1a" }}>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {categories.map(c => (
            <button key={c} onClick={() => setFilter(c)} style={{
              background: filter === c ? (CATEGORY_COLORS[c] || "#5DCAA5") + "22" : "transparent",
              border: `1px solid ${filter === c ? (CATEGORY_COLORS[c] || "#5DCAA5") + "55" : "#222"}`,
              borderRadius: 4, padding: "3px 8px", color: filter === c ? (CATEGORY_COLORS[c] || "#5DCAA5") : "#555",
              fontSize: 11, cursor: "pointer", fontFamily: "monospace", textTransform: "uppercase",
              letterSpacing: "0.05em",
            }}>{c}</button>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: "10px 10px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {filtered.map(tool => (
            <ToolCard key={tool.id} tool={tool} onRun={onRun} active={activeToolId === tool.id} />
          ))}
        </div>
      </div>
    </div>
  );
}

function Header({ scanCount }) {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{
      borderBottom: "1px solid #1a1a1a", padding: "0 20px",
      display: "flex", alignItems: "center", height: 52, gap: 16,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 28, height: 28, background: "#0d1e0d", border: "1px solid #1d9e7555", borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>◉</div>
        <span style={{ color: "#5DCAA5", fontFamily: "monospace", fontWeight: 700, fontSize: 15, letterSpacing: "0.12em" }}>SEC·OPS</span>
        <span style={{ color: "#333", fontFamily: "monospace", fontSize: 11 }}>|</span>
        <span style={{ color: "#555", fontFamily: "monospace", fontSize: 11, letterSpacing: "0.06em" }}>CYBERSECURITY DASHBOARD</span>
      </div>
      <div style={{ flex: 1 }} />
      <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
        <span style={{ color: "#2a4a2a", fontFamily: "monospace", fontSize: 11 }}>
          <span style={{ color: "#5DCAA5" }}>●</span> {scanCount} scans
        </span>
        <span style={{ color: "#333", fontFamily: "monospace", fontSize: 11 }}>
          {time.toLocaleTimeString("en-US", { hour12: false })}
        </span>
      </div>
    </div>
  );
}

function ResultHistory({ history, onSelect, activeIdx }) {
  if (history.length === 0) return (
    <div style={{ padding: "1rem", color: "#333", fontSize: 12, fontFamily: "monospace", textAlign: "center" }}>
      NO SCAN HISTORY
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {history.map((h, i) => (
        <button key={i} onClick={() => onSelect(i)} style={{
          background: activeIdx === i ? "#111" : "transparent",
          border: "none", borderBottom: "1px solid #111", cursor: "pointer",
          padding: "10px 12px", textAlign: "left", display: "flex", flexDirection: "column", gap: 2,
          borderLeft: activeIdx === i ? `2px solid ${h.tool.color}` : "2px solid transparent",
          transition: "all 0.1s",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ color: h.tool.color, fontSize: 12, fontFamily: "monospace", fontWeight: 600 }}>{h.tool.label}</span>
            {h.result && !h.result.error && h.result.risk_level && <RiskBadge level={h.result.risk_level} />}
          </div>
          <span style={{ color: "#444", fontSize: 11, fontFamily: "monospace" }}>{h.target}</span>
          <span style={{ color: "#333", fontSize: 10, fontFamily: "monospace" }}>{h.time}</span>
        </button>
      ))}
    </div>
  );
}

export default function App() {
  const [activeTool, setActiveTool] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [activeHistIdx, setActiveHistIdx] = useState(null);
  const [scanCount, setScanCount] = useState(0);

  const runTool = useCallback(async (tool, fields) => {
    setActiveTool(tool);
    setResult(null);
    setLoading(true);
    setActiveHistIdx(null);

    const target = Object.values(fields)[0] || "unknown";
    const ts = new Date().toLocaleTimeString("en-US", { hour12: false });

    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: "You are a cybersecurity analysis engine. Return ONLY valid JSON. No markdown, no backticks, no prose before or after. The JSON must be parseable directly.",
          messages: [{ role: "user", content: tool.prompt(fields) }],
        }),
      });

      const data = await response.json();
      const text = data.content?.map(c => c.text || "").join("") || "";
      const clean = text.replace(/```json|```/g, "").trim();
      let parsed;
      try {
        parsed = JSON.parse(clean);
      } catch {
        parsed = { summary: text, error: "Could not parse structured response — raw output above." };
      }

      setResult(parsed);
      setScanCount(c => c + 1);
      const entry = { tool, fields, target, time: ts, result: parsed };
      setHistory(h => [entry, ...h.slice(0, 19)]);
    } catch (err) {
      const errResult = { error: err.message || "Network error" };
      setResult(errResult);
      setHistory(h => [{ tool, fields, target, time: ts, result: errResult }, ...h.slice(0, 19)]);
    } finally {
      setLoading(false);
    }
  }, []);

  const selectHistory = (i) => {
    const h = history[i];
    setActiveTool(h.tool);
    setResult(h.result);
    setActiveHistIdx(i);
    setLoading(false);
  };

  return (
    <div style={{
      background: "#080808", minHeight: "100vh", color: "#e0e0e0",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
      display: "flex", flexDirection: "column",
    }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      <Header scanCount={scanCount} />

      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "320px 1fr 220px", minHeight: 0 }}>
        {/* Tools Sidebar */}
        <div style={{ borderRight: "1px solid #1a1a1a", overflowY: "auto" }}>
          <div style={{ padding: "10px 12px 6px", borderBottom: "1px solid #111" }}>
            <span style={{ fontSize: 10, color: "#444", letterSpacing: "0.1em", textTransform: "uppercase" }}>Security Tools ({TOOLS.length})</span>
          </div>
          <Sidebar tools={TOOLS} onRun={runTool} activeToolId={activeTool?.id} />
        </div>

        {/* Main Result Area */}
        <div style={{ display: "flex", flexDirection: "column", overflowY: "auto" }}>
          <div style={{ padding: "10px 16px 6px", borderBottom: "1px solid #111", display: "flex", alignItems: "center", gap: 10 }}>
            {activeTool ? (
              <>
                <span style={{ color: activeTool.color, fontSize: 14 }}>{activeTool.icon}</span>
                <span style={{ fontSize: 12, color: "#888", letterSpacing: "0.06em", textTransform: "uppercase" }}>{activeTool.label}</span>
              </>
            ) : (
              <span style={{ fontSize: 10, color: "#333", letterSpacing: "0.1em", textTransform: "uppercase" }}>Select a tool to begin</span>
            )}
          </div>

          {!activeTool ? (
            <WelcomeScreen tools={TOOLS} />
          ) : (
            <ResultPanel result={result} loading={loading} toolId={activeTool?.id} />
          )}
        </div>

        {/* History Panel */}
        <div style={{ borderLeft: "1px solid #1a1a1a", overflowY: "auto" }}>
          <div style={{ padding: "10px 12px 6px", borderBottom: "1px solid #111" }}>
            <span style={{ fontSize: 10, color: "#444", letterSpacing: "0.1em", textTransform: "uppercase" }}>Scan History</span>
          </div>
          <ResultHistory history={history} onSelect={selectHistory} activeIdx={activeHistIdx} />
        </div>
      </div>
    </div>
  );
}

function WelcomeScreen({ tools }) {
  const cats = [...new Set(tools.map(t => t.category))];
  return (
    <div style={{ padding: "2rem", flex: 1 }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ color: "#5DCAA5", fontFamily: "monospace", fontSize: 16, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>
          AI-Powered Security Assessment Platform
        </h2>
        <p style={{ color: "#555", fontSize: 13, lineHeight: 1.6 }}>
          Select a tool from the left panel, enter a target, and execute a simulated security scan powered by Claude.
        </p>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        {cats.map(cat => {
          const catTools = tools.filter(t => t.category === cat);
          return (
            <div key={cat} style={{ background: "#0c0c0c", border: "1px solid #1a1a1a", borderRadius: 8, padding: "12px 14px" }}>
              <div style={{ color: CATEGORY_COLORS[cat] || "#888", fontSize: 11, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, fontWeight: 600 }}>
                {cat} ({catTools.length})
              </div>
              {catTools.map(t => (
                <div key={t.id} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                  <span style={{ color: t.color, fontSize: 12 }}>{t.icon}</span>
                  <span style={{ color: "#555", fontSize: 12 }}>{t.label}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 20, padding: "10px 14px", background: "#0a1a0a", border: "1px solid #1a2a1a", borderRadius: 6 }}>
        <p style={{ color: "#3a6a3a", fontSize: 11, fontFamily: "monospace", lineHeight: 1.6, margin: 0 }}>
          ⚠ This dashboard performs AI-simulated security assessments for educational and research purposes. Always obtain proper authorization before scanning systems you do not own.
        </p>
      </div>
    </div>
  );
}