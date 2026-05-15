import { useState, useEffect, useRef, useCallback } from "react";

// ─── TYPES ────────────────────────────────────────────────────────────────────
const SKILLS = {
  NETWORK:  ["port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector","http_header_analyzer","network_recon","dns_security"],
  THREAT:   ["cve_lookup","ip_reputation","hash_lookup","ioc_extractor"],
  ANALYSIS: ["log_analyzer","vulnerability_scorer","vulnerability_assessment","web_app_scanner","api_security_audit","firewall_auditor"],
  CLOUD:    ["cloud_posture","container_scanner"],
  AUTH:     ["password_audit"],
  UTILITY:  ["summarizer","memory_writer"],
};

const ALL_SKILLS = Object.values(SKILLS).flat();

const SCAN_PRESETS = [
  { id:"full_recon",    label:"Full Recon",         icon:"🔍", skills:["dns_lookup","port_scanner","ssl_cert_inspector","http_header_analyzer","whois_lookup"], color:"#00d4ff" },
  { id:"vuln_assess",   label:"Vulnerability Scan",  icon:"🛡️", skills:["vulnerability_assessment","cve_lookup","vulnerability_scorer"], color:"#ff6b35" },
  { id:"web_audit",     label:"Web App Audit",       icon:"🌐", skills:["web_app_scanner","http_header_analyzer","api_security_audit"], color:"#7c3aed" },
  { id:"cloud_check",   label:"Cloud Posture",       icon:"☁️", skills:["cloud_posture","container_scanner"], color:"#059669" },
  { id:"threat_hunt",   label:"Threat Hunt",         icon:"🎯", skills:["ioc_extractor","ip_reputation","hash_lookup","log_analyzer"], color:"#dc2626" },
  { id:"dns_deep",      label:"DNS Deep Scan",       icon:"📡", skills:["dns_lookup","dns_security","whois_lookup"], color:"#d97706" },
  { id:"auth_audit",    label:"Auth Audit",          icon:"🔐", skills:["password_audit","ssl_cert_inspector"], color:"#0891b2" },
  { id:"full_pentest",  label:"Full Pentest",        icon:"💀", skills:ALL_SKILLS.slice(0,10), color:"#be185d" },
];

const LANGS = [
  { id:"python",     label:"Python",     color:"#3b82f6", api:"http://localhost:8000" },
  { id:"typescript", label:"TypeScript", color:"#10b981", api:"http://localhost:8001" },
  { id:"java",       label:"Java",       color:"#f59e0b", api:"http://localhost:8002" },
  { id:"rust",       label:"Rust",       color:"#ef4444", api:"http://localhost:8003" },
];

const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#eab308", LOW:"#22c55e", INFO:"#6b7280" };

function severity(output) {
  if (/\[CRITICAL\]/i.test(output)) return "CRITICAL";
  if (/\[HIGH\]/i.test(output))     return "HIGH";
  if (/\[MEDIUM\]/i.test(output))   return "MEDIUM";
  if (/\[LOW\]/i.test(output))      return "LOW";
  return "INFO";
}

// ─── MOCK SWARM ENGINE (runs real skill logic via Anthropic API) ─────────────
// In production: replace callSwarm with fetch() to your backend
async function callSwarm({ targets, skills, agentCount, useReact, lang }) {
  const results = [];
  for (const target of targets) {
    for (const skill of skills) {
      // Call Anthropic API to simulate the skill execution
      const prompt = `You are OMNIKON SEC·OPS, a professional security analyst.
Execute the "${skill}" security skill against target: "${target}"

Provide a realistic, detailed security assessment output as if you ran the actual tool.
Format: Use [CRITICAL], [HIGH], [MEDIUM], [LOW] severity tags.
Be specific with IPs, ports, findings, CVEs where relevant.
Keep output concise but professional (max 300 words).`;

      try {
        const resp = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "claude-sonnet-4-20250514",
            max_tokens: 600,
            messages: [{ role: "user", content: prompt }],
          }),
        });
        const data = await resp.json();
        const output = data.content?.[0]?.text || "No output";
        results.push({
          id:         `${Date.now()}-${Math.random()}`,
          task_id:    `task_${Math.random().toString(36).slice(2,8)}`,
          target,
          skill,
          lang:       lang.id,
          status:     "DONE",
          output,
          severity:   severity(output),
          duration_s: (Math.random() * 3 + 0.5).toFixed(2),
          timestamp:  new Date().toISOString(),
        });
      } catch (e) {
        results.push({
          id: `${Date.now()}-${Math.random()}`, task_id: `task_${Math.random().toString(36).slice(2,8)}`,
          target, skill, lang: lang.id, status:"FAILED", output:`Error: ${e.message}`,
          severity:"INFO", duration_s:"0.00", timestamp: new Date().toISOString(),
        });
      }
      // Small delay between calls
      await new Promise(r => setTimeout(r, 200));
    }
  }
  return results;
}

// ─── COMPONENTS ──────────────────────────────────────────────────────────────
function ScanBadge({ sev }) {
  return (
    <span style={{
      background: SEV_COLOR[sev] + "22", color: SEV_COLOR[sev],
      border: `1px solid ${SEV_COLOR[sev]}44`,
      padding:"2px 8px", borderRadius:4, fontSize:11, fontWeight:700,
      fontFamily:"'JetBrains Mono',monospace", letterSpacing:1,
    }}>{sev}</span>
  );
}

function PulsingDot({ color = "#22c55e" }) {
  return (
    <span style={{ position:"relative", display:"inline-block", width:10, height:10 }}>
      <span style={{
        position:"absolute", inset:0, borderRadius:"50%", background:color,
        animation:"ping 1.4s ease-in-out infinite", opacity:0.4,
      }}/>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color }}/>
    </span>
  );
}

function TerminalOutput({ text, maxHeight = 220 }) {
  const ref = useRef();
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [text]);
  if (!text) return null;
  // Colorize severity tags
  const colored = text
    .replace(/\[CRITICAL\]/g, '<span style="color:#ef4444;font-weight:700">[CRITICAL]</span>')
    .replace(/\[HIGH\]/g,     '<span style="color:#f97316;font-weight:700">[HIGH]</span>')
    .replace(/\[MEDIUM\]/g,   '<span style="color:#eab308;font-weight:700">[MEDIUM]</span>')
    .replace(/\[LOW\]/g,      '<span style="color:#22c55e;font-weight:700">[LOW]</span>')
    .replace(/\[WARN\]/g,     '<span style="color:#eab308;font-weight:700">[WARN]</span>')
    .replace(/✓/g,            '<span style="color:#22c55e">✓</span>')
    .replace(/✗/g,            '<span style="color:#ef4444">✗</span>');
  return (
    <div ref={ref} style={{
      maxHeight, overflow:"auto", background:"#0a0e1a", borderRadius:8,
      padding:"12px 14px", fontFamily:"'JetBrains Mono',monospace", fontSize:12,
      lineHeight:1.7, color:"#94a3b8", border:"1px solid #1e2a3a",
      whiteSpace:"pre-wrap", wordBreak:"break-all",
    }} dangerouslySetInnerHTML={{ __html: colored }} />
  );
}

function SkillChip({ name, selected, onClick, category }) {
  const catColors = { NETWORK:"#3b82f6", THREAT:"#ef4444", ANALYSIS:"#f97316", CLOUD:"#10b981", AUTH:"#8b5cf6", UTILITY:"#6b7280" };
  const c = catColors[category] || "#6b7280";
  return (
    <button onClick={onClick} style={{
      padding:"4px 10px", borderRadius:20, fontSize:11, cursor:"pointer",
      border:`1px solid ${selected ? c : c+"44"}`,
      background: selected ? c+"22" : "transparent",
      color: selected ? c : "#64748b",
      fontFamily:"'JetBrains Mono',monospace",
      transition:"all 0.15s", fontWeight: selected ? 600 : 400,
    }}>{name}</button>
  );
}

function AgentCard({ lang, count, status }) {
  return (
    <div style={{
      background:"#0f1621", border:"1px solid #1e2a3a", borderRadius:10,
      padding:"12px 16px", display:"flex", alignItems:"center", gap:10,
    }}>
      <div style={{
        width:36, height:36, borderRadius:8, background:lang.color+"22",
        display:"flex", alignItems:"center", justifyContent:"center",
        fontSize:16, border:`1px solid ${lang.color}44`,
      }}>
        {lang.id === "python" ? "🐍" : lang.id === "typescript" ? "📘" : lang.id === "java" ? "☕" : "🦀"}
      </div>
      <div style={{ flex:1 }}>
        <div style={{ color:"#e2e8f0", fontWeight:600, fontSize:13 }}>{lang.label}</div>
        <div style={{ color:"#475569", fontSize:11, fontFamily:"'JetBrains Mono',monospace" }}>
          {count} agents · {lang.api}
        </div>
      </div>
      <PulsingDot color={status === "online" ? "#22c55e" : "#ef4444"} />
    </div>
  );
}

function ResultCard({ result, expanded, onToggle }) {
  const sev = result.severity;
  return (
    <div style={{
      background:"#0f1621", border:`1px solid ${SEV_COLOR[sev]}33`,
      borderLeft:`3px solid ${SEV_COLOR[sev]}`,
      borderRadius:8, overflow:"hidden", cursor:"pointer",
      transition:"border-color 0.2s",
    }} onClick={onToggle}>
      <div style={{ padding:"12px 16px", display:"flex", alignItems:"center", gap:10 }}>
        <ScanBadge sev={sev} />
        <span style={{ color:"#94a3b8", fontSize:12, fontFamily:"'JetBrains Mono',monospace", flex:1 }}>
          <span style={{ color:"#e2e8f0", fontWeight:600 }}>{result.skill}</span>
          {" "}→ <span style={{ color:"#60a5fa" }}>{result.target}</span>
        </span>
        <span style={{ color:"#334155", fontSize:11 }}>{result.duration_s}s</span>
        <span style={{
          padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:600,
          background: LANGS.find(l=>l.id===result.lang)?.color + "22",
          color: LANGS.find(l=>l.id===result.lang)?.color,
          fontFamily:"'JetBrains Mono',monospace",
        }}>{result.lang}</span>
        <span style={{ color:"#334155", fontSize:13 }}>{expanded ? "▲" : "▼"}</span>
      </div>
      {expanded && (
        <div style={{ padding:"0 16px 14px" }}>
          <TerminalOutput text={result.output} />
        </div>
      )}
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────
export default function SecOpsDashboard() {
  const [targets, setTargets]           = useState("example.com\n192.168.1.1");
  const [selectedSkills, setSelSkills]  = useState(["port_scanner","dns_lookup","ssl_cert_inspector"]);
  const [selectedLangs, setSelLangs]    = useState(["python"]);
  const [agentCount, setAgentCount]     = useState(3);
  const [useReact, setUseReact]         = useState(false);
  const [scanning, setScanning]         = useState(false);
  const [results, setResults]           = useState([]);
  const [expandedId, setExpandedId]     = useState(null);
  const [progress, setProgress]         = useState(0);
  const [log, setLog]                   = useState([]);
  const [tab, setTab]                   = useState("scan"); // scan | results | swarm | history
  const [history, setHistory]           = useState([]);
  const [statsAnim, setStatsAnim]       = useState(false);
  const logRef = useRef();

  const addLog = useCallback((msg, type="info") => {
    setLog(l => [...l.slice(-60), { msg, type, ts: new Date().toLocaleTimeString() }]);
  }, []);

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [log]);

  const toggleSkill = (s) => setSelSkills(prev => prev.includes(s) ? prev.filter(x=>x!==s) : [...prev, s]);
  const applyPreset = (p) => { setSelSkills(p.skills); addLog(`Applied preset: ${p.label}`, "success"); };

  const runScan = async () => {
    const tgtList = targets.split("\n").map(t=>t.trim()).filter(Boolean);
    if (!tgtList.length)    { addLog("⚠ No targets specified", "error"); return; }
    if (!selectedSkills.length) { addLog("⚠ No skills selected", "error"); return; }
    if (!selectedLangs.length)  { addLog("⚠ No language selected", "error"); return; }

    setScanning(true); setResults([]); setProgress(0);
    const total = tgtList.length * selectedSkills.length;
    let done = 0;

    addLog(`🚀 Swarm launched: ${agentCount} agents, ${tgtList.length} targets, ${selectedSkills.length} skills`,"success");

    const allResults = [];
    for (const langId of selectedLangs) {
      const lang = LANGS.find(l => l.id === langId);
      addLog(`[${lang.label}] Dispatching ${total} tasks to ${agentCount} agents…`);
      const batchResults = await callSwarm({
        targets: tgtList,
        skills: selectedSkills,
        agentCount,
        useReact,
        lang,
      });
      for (const r of batchResults) {
        done++;
        setProgress(Math.round(done / (total * selectedLangs.length) * 100));
        setResults(prev => [r, ...prev]);
        allResults.push(r);
        const icon = r.severity === "CRITICAL" ? "🔴" : r.severity === "HIGH" ? "🟠" : r.severity === "LOW" ? "🟢" : "🟡";
        addLog(`${icon} [${lang.label}] ${r.skill} → ${r.target}: ${r.severity}`, r.severity === "CRITICAL" ? "error" : "info");
      }
    }

    // Save to history
    setHistory(h => [{
      id: Date.now(),
      ts: new Date().toLocaleString(),
      targets: tgtList,
      skills: selectedSkills,
      langs: selectedLangs,
      count: allResults.length,
      critical: allResults.filter(r=>r.severity==="CRITICAL").length,
    }, ...h.slice(0,19)]);

    setScanning(false); setProgress(100); setStatsAnim(true);
    addLog(`✅ Scan complete: ${allResults.length} results`, "success");
    setTimeout(() => setStatsAnim(false), 800);
    setTab("results");
  };

  const critical = results.filter(r=>r.severity==="CRITICAL").length;
  const high     = results.filter(r=>r.severity==="HIGH").length;
  const done     = results.filter(r=>r.status==="DONE").length;

  const styles = {
    app: {
      minHeight:"100vh", background:"#060c14",
      fontFamily:"'Syne','Space Grotesk',sans-serif",
      color:"#e2e8f0",
    },
    header: {
      borderBottom:"1px solid #1e2a3a", padding:"0 28px",
      display:"flex", alignItems:"center", justifyContent:"space-between",
      height:60, background:"#080e18",
    },
    logo: {
      display:"flex", alignItems:"center", gap:10,
      fontSize:15, fontWeight:800, letterSpacing:3, color:"#e2e8f0",
      textTransform:"uppercase",
    },
    logoAccent: { color:"#00d4ff" },
    nav: { display:"flex", gap:4 },
    navBtn: (active) => ({
      padding:"6px 18px", borderRadius:6, cursor:"pointer",
      background: active ? "#162032" : "transparent",
      border: active ? "1px solid #1e3a5f" : "1px solid transparent",
      color: active ? "#60a5fa" : "#475569",
      fontSize:13, fontWeight:600, transition:"all 0.15s",
    }),
    main: { display:"grid", gridTemplateColumns:"380px 1fr", gap:0, height:"calc(100vh - 60px)" },
    sidebar: {
      borderRight:"1px solid #1e2a3a", overflow:"auto",
      background:"#080e18", padding:"20px",
    },
    content: { overflow:"auto", padding:"20px" },
    section: { marginBottom:20 },
    label: { fontSize:11, fontWeight:700, letterSpacing:2, color:"#475569", textTransform:"uppercase", marginBottom:8, display:"block" },
    textarea: {
      width:"100%", background:"#0a0e1a", border:"1px solid #1e2a3a", borderRadius:8,
      color:"#e2e8f0", padding:"10px 12px", fontSize:12, fontFamily:"'JetBrains Mono',monospace",
      resize:"vertical", minHeight:80, outline:"none", boxSizing:"border-box",
    },
    statCard: (accent, anim) => ({
      background:"#0f1621", border:`1px solid ${accent}33`,
      borderRadius:10, padding:"14px 18px", flex:1,
      transform: anim ? "scale(1.04)" : "scale(1)",
      transition:"transform 0.3s ease",
    }),
    runBtn: {
      width:"100%", padding:"13px", borderRadius:10,
      background: scanning ? "#1e2a3a" : "linear-gradient(135deg,#0ea5e9,#6366f1)",
      border:"none", color:"#fff", fontSize:14, fontWeight:800,
      cursor: scanning ? "not-allowed" : "pointer", letterSpacing:1,
      boxShadow: scanning ? "none" : "0 4px 20px #0ea5e933",
      transition:"all 0.2s",
    },
    progressBar: {
      height:4, background:"#1e2a3a", borderRadius:2, overflow:"hidden", marginTop:8,
    },
    progressFill: {
      height:"100%", width:`${progress}%`,
      background:"linear-gradient(90deg,#0ea5e9,#6366f1)",
      transition:"width 0.3s ease",
    },
  };

  return (
    <div style={styles.app}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar { width:4px; height:4px; }
        ::-webkit-scrollbar-track { background:#0a0e1a; }
        ::-webkit-scrollbar-thumb { background:#1e2a3a; border-radius:2px; }
        @keyframes ping { 0%,100%{transform:scale(1);opacity:0.4} 50%{transform:scale(1.8);opacity:0} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes scan { 0%{background-position:0 0} 100%{background-position:0 100%} }
      `}</style>

      {/* Header */}
      <header style={styles.header}>
        <div style={styles.logo}>
          <div style={{
            width:32, height:32, borderRadius:8,
            background:"linear-gradient(135deg,#0ea5e9,#6366f1)",
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:16,
          }}>🛡️</div>
          <span>OMNIKON <span style={styles.logoAccent}>SEC</span>·OPS</span>
          <span style={{ fontSize:10, color:"#334155", fontFamily:"'JetBrains Mono',monospace", letterSpacing:1 }}>v1.0.2</span>
        </div>
        <nav style={styles.nav}>
          {[["scan","⚡ Scan"],["results","📊 Results"],["swarm","🐝 Swarm"],["history","📁 History"]].map(([id,label]) => (
            <button key={id} style={styles.navBtn(tab===id)} onClick={()=>setTab(id)}>{label}</button>
          ))}
        </nav>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          {results.length > 0 && critical > 0 && (
            <div style={{ background:"#ef444422", border:"1px solid #ef444444", borderRadius:6, padding:"4px 12px", fontSize:12, color:"#ef4444", fontWeight:700 }}>
              🔴 {critical} CRITICAL
            </div>
          )}
          <PulsingDot color="#22c55e" />
          <span style={{ fontSize:11, color:"#475569" }}>ONLINE</span>
        </div>
      </header>

      <div style={styles.main}>
        {/* SIDEBAR */}
        <aside style={styles.sidebar}>

          {/* TARGETS */}
          <div style={styles.section}>
            <label style={styles.label}>🎯 Targets</label>
            <textarea
              style={styles.textarea}
              value={targets}
              onChange={e=>setTargets(e.target.value)}
              placeholder={"example.com\n192.168.1.1\n10.0.0.0/24"}
            />
            <div style={{ fontSize:11, color:"#334155", marginTop:4 }}>
              {targets.split("\n").filter(t=>t.trim()).length} target(s) · one per line
            </div>
          </div>

          {/* LANGUAGE */}
          <div style={styles.section}>
            <label style={styles.label}>🌐 Language Backend</label>
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {LANGS.map(l => (
                <button key={l.id} onClick={() => setSelLangs(prev => prev.includes(l.id) ? prev.filter(x=>x!==l.id) : [...prev, l.id])} style={{
                  padding:"5px 12px", borderRadius:6, cursor:"pointer", fontSize:12, fontWeight:600,
                  border:`1px solid ${selectedLangs.includes(l.id) ? l.color : l.color+"44"}`,
                  background: selectedLangs.includes(l.id) ? l.color+"22" : "transparent",
                  color: selectedLangs.includes(l.id) ? l.color : "#475569",
                  transition:"all 0.15s",
                }}>{l.label}</button>
              ))}
            </div>
          </div>

          {/* AGENTS */}
          <div style={styles.section}>
            <label style={styles.label}>🤖 Agent Count: {agentCount}</label>
            <input type="range" min={1} max={20} value={agentCount} onChange={e=>setAgentCount(+e.target.value)}
              style={{ width:"100%", accentColor:"#0ea5e9" }} />
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:"#334155", marginTop:2 }}>
              <span>1</span><span>10</span><span>20</span>
            </div>
          </div>

          {/* REACT MODE */}
          <div style={{ ...styles.section, display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <div>
              <div style={{ fontSize:13, color:"#e2e8f0", fontWeight:600 }}>ReAct Mode</div>
              <div style={{ fontSize:11, color:"#475569" }}>Autonomous Thought→Action loop</div>
            </div>
            <div onClick={() => setUseReact(!useReact)} style={{
              width:42, height:24, borderRadius:12, cursor:"pointer",
              background: useReact ? "#0ea5e9" : "#1e2a3a", position:"relative", transition:"background 0.2s",
            }}>
              <div style={{
                width:18, height:18, borderRadius:"50%", background:"#fff",
                position:"absolute", top:3, left: useReact ? 21 : 3, transition:"left 0.2s",
              }}/>
            </div>
          </div>

          {/* SCAN PRESETS */}
          <div style={styles.section}>
            <label style={styles.label}>⚡ Quick Presets</label>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6 }}>
              {SCAN_PRESETS.map(p => (
                <button key={p.id} onClick={()=>applyPreset(p)} style={{
                  padding:"8px 6px", borderRadius:8, cursor:"pointer",
                  border:`1px solid ${p.color}33`, background:"transparent",
                  color:"#94a3b8", fontSize:11, textAlign:"left",
                  transition:"all 0.15s", fontFamily:"'JetBrains Mono',monospace",
                }}>
                  <div style={{ fontSize:16, marginBottom:2 }}>{p.icon}</div>
                  <div style={{ color:p.color, fontWeight:600, fontSize:10 }}>{p.label}</div>
                  <div style={{ color:"#334155", fontSize:9 }}>{p.skills.length} skills</div>
                </button>
              ))}
            </div>
          </div>

          {/* SKILLS */}
          <div style={styles.section}>
            <label style={styles.label}>🔧 Skills ({selectedSkills.length} selected)</label>
            {Object.entries(SKILLS).map(([cat, skills]) => (
              <div key={cat} style={{ marginBottom:10 }}>
                <div style={{ fontSize:10, color:"#334155", marginBottom:5, letterSpacing:1 }}>{cat}</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:4 }}>
                  {skills.map(s => (
                    <SkillChip key={s} name={s.replace(/_/g," ")} category={cat}
                      selected={selectedSkills.includes(s)} onClick={()=>toggleSkill(s)} />
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* RUN BUTTON */}
          <button style={styles.runBtn} onClick={runScan} disabled={scanning}>
            {scanning ? `⚙️ Scanning… ${progress}%` : "⚡ LAUNCH SWARM"}
          </button>
          {scanning && <div style={styles.progressBar}><div style={styles.progressFill}/></div>}

        </aside>

        {/* MAIN CONTENT */}
        <main style={styles.content}>

          {/* SCAN TAB */}
          {tab === "scan" && (
            <div>
              {/* Stats */}
              <div style={{ display:"flex", gap:12, marginBottom:20 }}>
                {[
                  ["Total Results", results.length, "#60a5fa"],
                  ["Critical",      critical,        "#ef4444"],
                  ["High",          high,            "#f97316"],
                  ["Done",          done,            "#22c55e"],
                ].map(([label, val, color]) => (
                  <div key={label} style={styles.statCard(color, statsAnim)}>
                    <div style={{ fontSize:24, fontWeight:800, color }}>{val}</div>
                    <div style={{ fontSize:11, color:"#475569", letterSpacing:1, textTransform:"uppercase" }}>{label}</div>
                  </div>
                ))}
              </div>

              {/* Live log */}
              <div style={{ background:"#080e18", border:"1px solid #1e2a3a", borderRadius:10, padding:16, marginBottom:20 }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                  {scanning && <PulsingDot />}
                  <span style={{ fontSize:12, fontWeight:700, letterSpacing:2, color:"#475569", textTransform:"uppercase" }}>
                    Live Console
                  </span>
                </div>
                <div ref={logRef} style={{
                  height:160, overflow:"auto", fontFamily:"'JetBrains Mono',monospace",
                  fontSize:11, lineHeight:1.8,
                }}>
                  {log.length === 0 ? (
                    <div style={{ color:"#1e2a3a" }}>Launch a scan to see live output…</div>
                  ) : log.map((l,i) => (
                    <div key={i} style={{
                      color: l.type==="error" ? "#ef4444" : l.type==="success" ? "#22c55e" : "#475569",
                    }}>
                      <span style={{ color:"#1e2a3a" }}>[{l.ts}]</span> {l.msg}
                    </div>
                  ))}
                </div>
              </div>

              {/* Recent results preview */}
              {results.length > 0 && (
                <div>
                  <div style={{ fontSize:12, fontWeight:700, letterSpacing:2, color:"#475569", textTransform:"uppercase", marginBottom:10 }}>
                    Latest Findings
                  </div>
                  <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                    {results.slice(0,5).map(r => (
                      <ResultCard key={r.id} result={r}
                        expanded={expandedId===r.id}
                        onToggle={()=>setExpandedId(expandedId===r.id?null:r.id)} />
                    ))}
                    {results.length > 5 && (
                      <button onClick={()=>setTab("results")} style={{
                        padding:"8px", borderRadius:8, border:"1px dashed #1e2a3a",
                        background:"transparent", color:"#475569", cursor:"pointer", fontSize:12,
                      }}>
                        View all {results.length} results →
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* RESULTS TAB */}
          {tab === "results" && (
            <div>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
                <div style={{ fontSize:18, fontWeight:800, color:"#e2e8f0" }}>
                  Results <span style={{ color:"#475569", fontSize:14 }}>({results.length})</span>
                </div>
                <div style={{ display:"flex", gap:6 }}>
                  {["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(f => (
                    <button key={f} style={{
                      padding:"4px 10px", borderRadius:6, cursor:"pointer", fontSize:11, fontWeight:600,
                      border:`1px solid ${SEV_COLOR[f] || "#1e2a3a"}44`,
                      background:"transparent",
                      color: SEV_COLOR[f] || "#475569",
                      fontFamily:"'JetBrains Mono',monospace",
                    }}>{f}</button>
                  ))}
                </div>
              </div>
              {results.length === 0 ? (
                <div style={{ textAlign:"center", padding:"60px 0", color:"#1e2a3a", fontSize:14 }}>
                  No results yet. Launch a scan from the Scan tab.
                </div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                  {results.map(r => (
                    <ResultCard key={r.id} result={r}
                      expanded={expandedId===r.id}
                      onToggle={()=>setExpandedId(expandedId===r.id?null:r.id)} />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SWARM TAB */}
          {tab === "swarm" && (
            <div>
              <div style={{ fontSize:18, fontWeight:800, color:"#e2e8f0", marginBottom:16 }}>Swarm Pool</div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:20 }}>
                {LANGS.map(l => (
                  <AgentCard key={l.id} lang={l}
                    count={selectedLangs.includes(l.id) ? agentCount : 0}
                    status={selectedLangs.includes(l.id) ? "online" : "offline"} />
                ))}
              </div>

              <div style={{ background:"#0f1621", border:"1px solid #1e2a3a", borderRadius:10, padding:16, marginBottom:16 }}>
                <div style={{ fontSize:12, fontWeight:700, letterSpacing:2, color:"#475569", textTransform:"uppercase", marginBottom:12 }}>
                  Swarm Architecture
                </div>
                <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:"#475569", lineHeight:2 }}>
                  <div style={{ color:"#60a5fa" }}>SwarmManager</div>
                  {["AgentPool ── AgentWorker × N  (per language)","PriorityQueue ── CRITICAL → HIGH → NORMAL → LOW","MemoryManager 2.1–2.5 (per agent, isolated archive)","ReActEngine ── Thought → Action → Observation loop","22 SecOps Skills ── network · threat · analysis · cloud"].map((line,i) => (
                    <div key={i} style={{ paddingLeft:16 }}>
                      <span style={{ color:"#1e3a5f" }}>├── </span>{line}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:10 }}>
                {[
                  ["Total Tasks Run", results.length],
                  ["Critical Findings", critical],
                  ["Active Agents", selectedLangs.length * agentCount],
                  ["Scan Coverage", `${selectedSkills.length}/22`],
                  ["Languages Active", selectedLangs.length],
                  ["ReAct Mode", useReact ? "ON" : "OFF"],
                ].map(([label,val]) => (
                  <div key={label} style={{ background:"#0f1621", border:"1px solid #1e2a3a", borderRadius:8, padding:"14px 16px" }}>
                    <div style={{ fontSize:20, fontWeight:800, color:"#60a5fa" }}>{val}</div>
                    <div style={{ fontSize:11, color:"#475569", textTransform:"uppercase", letterSpacing:1 }}>{label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* HISTORY TAB */}
          {tab === "history" && (
            <div>
              <div style={{ fontSize:18, fontWeight:800, color:"#e2e8f0", marginBottom:16 }}>Scan History</div>
              {history.length === 0 ? (
                <div style={{ textAlign:"center", padding:"60px 0", color:"#1e2a3a" }}>No scan history yet.</div>
              ) : history.map(h => (
                <div key={h.id} style={{
                  background:"#0f1621", border:"1px solid #1e2a3a", borderRadius:8,
                  padding:"14px 16px", marginBottom:8, display:"flex", alignItems:"center", gap:12,
                }}>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12, color:"#94a3b8" }}>
                      <span style={{ color:"#60a5fa" }}>{h.targets.join(", ")}</span>
                      {" · "}{h.skills.length} skills · {h.langs.join("+")}
                    </div>
                    <div style={{ fontSize:11, color:"#334155", fontFamily:"'JetBrains Mono',monospace", marginTop:3 }}>{h.ts}</div>
                  </div>
                  <div style={{ textAlign:"right" }}>
                    <div style={{ fontSize:14, fontWeight:700, color:"#e2e8f0" }}>{h.count} results</div>
                    {h.critical > 0 && <div style={{ fontSize:11, color:"#ef4444" }}>{h.critical} critical</div>}
                  </div>
                </div>
              ))}
            </div>
          )}

        </main>
      </div>
    </div>
  );
}
