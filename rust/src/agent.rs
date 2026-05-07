// =============================================================================
// agent.rs
// =============================================================================
// Project  : OMNIKON SEC·OPS — AI Memory Agent
// Version  : v1.0.2
// Language : Rust 1.75+
// License  : MIT
//
// Full ReAct AI agent with 22 production SecOps skills (no mocks).
// UI-aligned with cybersec-dashboard.jsx tool set.
//
// Skills:
//   NETWORK  : port_scanner, dns_lookup, whois_lookup, ssl_cert_inspector,
//              http_header_analyzer, network_recon, dns_security
//   THREAT   : cve_lookup, ip_reputation, hash_lookup, ioc_extractor
//   ANALYSIS : log_analyzer, vulnerability_scorer, vulnerability_assessment,
//              web_app_scanner, api_security_audit, firewall_auditor
//   CLOUD    : cloud_posture, container_scanner
//   AUTH     : password_audit
//   UTILITY  : summarizer, memory_writer
//
// Optional env vars:
//   DEEPSEEK_API_KEY     (required)
//   ABUSEIPDB_API_KEY    (optional — live IP reputation)
//   VIRUSTOTAL_API_KEY   (optional — live hash lookup)
//
// Usage:
//   export DEEPSEEK_API_KEY=sk-...
//   cargo run --release
//   cargo run --release -- --archive /path/to/memory.jsonl
// =============================================================================

mod memory_manager;

use memory_manager::{MemoryManager, TraceType};

use std::{
    collections::{HashMap, HashSet},
    env,
    io::{self, BufRead, Write},
    net::{InetAddress, TcpStream},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::Command,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use regex::Regex;
use serde::Deserialize;

// ─────────────────────────────────────────────────────────────────────────────
// DeepSeek API
// ─────────────────────────────────────────────────────────────────────────────

const DEEPSEEK_URL:   &str = "https://api.deepseek.com/v1/chat/completions";
const DEEPSEEK_MODEL: &str = "deepseek-chat";

fn api_key() -> String {
    env::var("DEEPSEEK_API_KEY")
        .expect("DEEPSEEK_API_KEY not set.\n  export DEEPSEEK_API_KEY=sk-...")
}

fn call_deepseek(
    system:   &str,
    messages: &[memory_manager::Message],
    temperature: f64,
) -> Result<String, String> {
    let mut msgs = vec![serde_json::json!({"role":"system","content":system})];
    for m in messages {
        msgs.push(serde_json::json!({"role":m.role,"content":m.content}));
    }
    let body = serde_json::json!({
        "model":       DEEPSEEK_MODEL,
        "max_tokens":  4096_u32,
        "temperature": temperature,
        "messages":    msgs,
    });
    let resp = ureq::post(DEEPSEEK_URL)
        .set("Content-Type",  "application/json")
        .set("Authorization", &format!("Bearer {}", api_key()))
        .timeout(Duration::from_secs(90))
        .send_json(body)
        .map_err(|e| format!("DeepSeek request error: {}", e))?;

    let parsed: serde_json::Value = resp.into_json()
        .map_err(|e| format!("DeepSeek parse error: {}", e))?;
    parsed["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "DeepSeek: empty choices".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helper
// ─────────────────────────────────────────────────────────────────────────────

struct HttpResp {
    status:  u16,
    headers: HashMap<String, String>,
    body:    String,
}

fn http_get(url: &str, extra_headers: &[(&str, &str)]) -> Result<HttpResp, String> {
    let mut req = ureq::get(url)
        .set("User-Agent", "OMNIKON-SecOps/1.0.2")
        .timeout(Duration::from_secs(15));
    for (k, v) in extra_headers {
        req = req.set(k, v);
    }
    let resp = req.call().map_err(|e| format!("HTTP error: {}", e))?;
    let status = resp.status();
    let mut headers = HashMap::new();
    for name in resp.headers_names() {
        if let Some(v) = resp.header(&name) {
            headers.insert(name.to_lowercase(), v.to_string());
        }
    }
    let body = resp.into_string().unwrap_or_default();
    Ok(HttpResp { status, headers, body })
}

fn http_head(url: &str, extra_headers: &[(&str, &str)]) -> Result<HttpResp, String> {
    // ureq follows redirects on GET; use GET with limited body for HEAD equivalent
    http_get(url, extra_headers)
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP scan helper
// ─────────────────────────────────────────────────────────────────────────────

fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
        80 => "http", 110 => "pop3", 143 => "imap", 389 => "ldap", 443 => "https",
        445 => "smb", 3306 => "mysql", 3389 => "rdp", 5432 => "postgres",
        6379 => "redis", 8080 => "http-alt", 8443 => "https-alt",
        27017 => "mongodb", 5900 => "vnc", 11211 => "memcached",
        _ => "unknown",
    }
}

fn tcp_probe(host: &str, port: u16, timeout_ms: u64) -> (bool, String) {
    let addr = format!("{}:{}", host, port);
    match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        Duration::from_millis(timeout_ms),
    ) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_millis(400))).ok();
            let mut banner = vec![0u8; 256];
            let banner_str = match stream.read(&mut banner) {
                Ok(n) if n > 0 => String::from_utf8_lossy(&banner[..n.min(80)])
                    .trim()
                    .replace(['\n', '\r'], " ")
                    .to_string(),
                _ => String::new(),
            };
            (true, banner_str)
        }
        Err(_) => (false, String::new()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Skill system
// ─────────────────────────────────────────────────────────────────────────────

pub struct SkillResult {
    pub skill:            String,
    pub success:          bool,
    pub output:           String,
    pub store_to_archive: bool,
    pub archive_tags:     Vec<String>,
}

impl SkillResult {
    fn ok(skill: &str, output: String, tags: Vec<&str>) -> Self {
        Self { skill: skill.to_string(), success: true, output,
               store_to_archive: !tags.is_empty(),
               archive_tags: tags.iter().map(|t| t.to_string()).collect() }
    }
    fn err(skill: &str, msg: impl Into<String>) -> Self {
        Self { skill: skill.to_string(), success: false, output: format!("⚠ {}", msg.into()),
               store_to_archive: false, archive_tags: vec![] }
    }
}

trait Skill: Send + Sync {
    fn name(&self)             -> &'static str;
    fn description(&self)      -> &'static str;
    fn usage(&self)            -> &'static str;
    fn trigger_patterns(&self) -> &'static [&'static str];
    fn run(&self, args: &str, mm: &MemoryManager) -> SkillResult;
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK SKILLS
// ═════════════════════════════════════════════════════════════════════════════

struct PortScannerSkill;
impl Skill for PortScannerSkill {
    fn name(&self)             -> &'static str { "port_scanner" }
    fn description(&self)      -> &'static str { "TCP connect scan on host:ports — real network scan" }
    fn usage(&self)            -> &'static str { "port_scanner <host> <ports>  e.g. 192.168.1.1 22,80,443" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["port scan","scan ports","open ports","port check"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.len() < 2 { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let host = parts[0]; let port_spec = parts[1];
        let mut ports = Vec::new();
        for seg in port_spec.split(',') {
            let seg = seg.trim();
            if seg.contains('-') {
                let ab: Vec<u16> = seg.split('-').filter_map(|x| x.parse().ok()).collect();
                if ab.len() == 2 { for p in ab[0]..=ab[1].min(ab[0]+499) { ports.push(p); } }
            } else if let Ok(p) = seg.parse::<u16>() { ports.push(p); }
        }
        if ports.len() > 500 { return SkillResult::err(self.name(), "Max 500 ports per scan"); }

        use std::thread;
        let host_str = host.to_string();
        let results: Vec<(u16, bool, String)> = {
            let handles: Vec<_> = ports.iter().map(|&port| {
                let h = host_str.clone();
                thread::spawn(move || { let (open, banner) = tcp_probe(&h, port, 1200); (port, open, banner) })
            }).collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        };
        let mut open: Vec<(u16, String)> = results.into_iter()
            .filter(|(_, open, _)| *open)
            .map(|(p, _, b)| (p, b))
            .collect();
        open.sort_by_key(|r| r.0);

        if open.is_empty() {
            return SkillResult::ok(self.name(),
                format!("**Port Scan** {} — no open ports in {}", host, port_spec),
                vec!["port_scan", host]);
        }
        let mut lines = vec![format!("**Port Scan** {} — {} open port(s)\n", host, open.len())];
        for (port, banner) in &open {
            let svc = well_known_service(*port);
            let b = if banner.is_empty() { String::new() } else { format!(" — `{}`", banner) };
            lines.push(format!("  {:5}/tcp  OPEN  {:<12}{}", port, svc, b));
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["port_scan", host, &format!("open:{}", open.len())])
    }
}

struct DnsLookupSkill;
impl Skill for DnsLookupSkill {
    fn name(&self)             -> &'static str { "dns_lookup" }
    fn description(&self)      -> &'static str { "DNS resolution using system resolver + dig" }
    fn usage(&self)            -> &'static str { "dns_lookup <hostname|ip> [A|MX|TXT|NS|PTR]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["dns lookup","resolve hostname","dns record","nslookup"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() || parts[0].is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let target = parts[0]; let rtype = parts.get(1).copied().unwrap_or("A").to_uppercase();
        let mut lines = vec![format!("**DNS Lookup** `{}` ({})\n", target, rtype)];
        if rtype == "A" {
            use std::net::ToSocketAddrs;
            match format!("{}:0", target).to_socket_addrs() {
                Ok(addrs) => { let ips: HashSet<String> = addrs.map(|a| a.ip().to_string()).collect();
                               ips.iter().for_each(|ip| lines.push(format!("  A     {}", ip))); }
                Err(e) => return SkillResult::err(self.name(), format!("DNS error: {}", e)),
            }
        } else {
            match Command::new("dig").args(["+short", &rtype, target]).output() {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if stdout.trim().is_empty() { lines.push(format!("  No {} records found", rtype)); }
                    else { stdout.lines().for_each(|l| lines.push(format!("  {:<5} {}", rtype, l.trim()))); }
                }
                Err(_) => lines.push("  dig not installed; only A records via stdlib".to_string()),
            }
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["dns", target])
    }
}

struct WhoisLookupSkill;
impl Skill for WhoisLookupSkill {
    fn name(&self)             -> &'static str { "whois_lookup" }
    fn description(&self)      -> &'static str { "WHOIS registration data via TCP port 43" }
    fn usage(&self)            -> &'static str { "whois_lookup <domain|ip>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["whois","domain registration","ip owner","registrar"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let target = args.trim();
        if target.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let is_ip  = target.parse::<IpAddr>().is_ok();
        let server = if is_ip { "whois.arin.net" } else {
            match target.rsplit('.').next().unwrap_or("") {
                "com" | "net" => "whois.verisign-grs.com",
                "org" => "whois.pir.org",
                "io"  => "whois.nic.io",
                _     => "whois.iana.org",
            }
        };
        fn whois_query(server: &str, target: &str) -> Result<String, String> {
            use std::io::{Read, Write};
            let mut stream = TcpStream::connect(format!("{}:43", server))
                .map_err(|e| format!("WHOIS connect failed: {}", e))?;
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.write_all(format!("{}\r\n", target).as_bytes())
                .map_err(|e| e.to_string())?;
            let mut raw = String::new();
            stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
            Ok(raw)
        }
        let raw = match whois_query(server, target) {
            Ok(r) => r,
            Err(e) => return SkillResult::err(self.name(), e),
        };
        let keys = ["Registrar","Creation Date","Expiry Date","Updated Date",
                    "Name Server","Status","Organization","OrgName","Country","NetRange"];
        let mut found = HashMap::new();
        for line in raw.lines() {
            for key in &keys {
                if line.trim().to_lowercase().starts_with(&format!("{}:", key.to_lowercase()))
                   && !found.contains_key(*key) {
                    if let Some(val) = line.splitn(2, ':').nth(1) {
                        found.insert(*key, val.trim().to_string());
                    }
                }
            }
        }
        let mut lines = vec![format!("**WHOIS** `{}` (via {})\n", target, server)];
        if found.is_empty() { lines.push(raw.chars().take(800).collect()); }
        else { for k in &keys { if let Some(v) = found.get(k) { lines.push(format!("  {:<22}: {}", k, v)); } } }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["whois", target])
    }
}

struct SslCertInspectorSkill;
impl Skill for SslCertInspectorSkill {
    fn name(&self)             -> &'static str { "ssl_cert_inspector" }
    fn description(&self)      -> &'static str { "Inspect TLS certificate: expiry, issuer, SANs, cipher, protocol" }
    fn usage(&self)            -> &'static str { "ssl_cert_inspector <hostname> [port]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["ssl cert","tls certificate","certificate expiry","https cert"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let host = parts[0];
        let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
        // Use openssl s_client via subprocess — most reliable cross-platform
        match Command::new("openssl")
            .args(["s_client", "-connect", &format!("{}:{}", host, port),
                   "-servername", host, "-brief"])
            .output()
        {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let combined = format!("{}{}", stderr, stdout);
                let subject  = combined.lines().find(|l| l.contains("subject=")).map(|l| l.trim().to_string()).unwrap_or_default();
                let issuer   = combined.lines().find(|l| l.contains("issuer=")).map(|l| l.trim().to_string()).unwrap_or_default();
                let expiry   = combined.lines().find(|l| l.contains("notAfter")).map(|l| l.trim().to_string()).unwrap_or_default();
                let proto    = combined.lines().find(|l| l.contains("Protocol") || l.contains("TLSv")).map(|l| l.trim().to_string()).unwrap_or_default();
                let cipher   = combined.lines().find(|l| l.contains("Cipher") || l.contains("cipher")).map(|l| l.trim().to_string()).unwrap_or_default();
                let expired  = combined.to_lowercase().contains("certificate has expired");
                let tag = if expired { "[CRITICAL] EXPIRED" } else if combined.contains("verify error") { "[WARN] Cert error" } else { "valid" };
                let lines = vec![
                    format!("**SSL Certificate** `{}:{}`\n", host, port),
                    format!("  Status  : {}", tag),
                    subject, issuer, expiry, proto, cipher,
                ];
                let mut tags = vec!["ssl_cert", host];
                if expired { tags.push("expired_cert"); }
                SkillResult::ok(self.name(), lines.join("\n"), tags)
            }
            Err(_) => {
                // Fall back to raw TLS connect without cert validation
                match TcpStream::connect_timeout(
                    &format!("{}:{}", host, port).parse().unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
                    Duration::from_secs(5),
                ) {
                    Ok(_) => SkillResult::ok(self.name(),
                        format!("**SSL Certificate** `{}:{}`\n  Port open — install openssl CLI for full certificate details", host, port),
                        vec!["ssl_cert", host]),
                    Err(e) => SkillResult::err(self.name(), format!("Connection failed: {}", e)),
                }
            }
        }
    }
}

struct HttpHeaderAnalyzerSkill;
impl Skill for HttpHeaderAnalyzerSkill {
    fn name(&self)             -> &'static str { "http_header_analyzer" }
    fn description(&self)      -> &'static str { "Fetch HTTP headers and audit security posture" }
    fn usage(&self)            -> &'static str { "http_header_analyzer <url>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["http headers","security headers","check hsts","header analysis"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let url = if args.trim().starts_with("http") { args.trim().to_string() } else { format!("https://{}", args.trim()) };
        if url.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let resp = match http_head(&url, &[]) { Ok(r) => r, Err(e) => return SkillResult::err(self.name(), e) };
        let sec_hdrs = [
            ("strict-transport-security", "HSTS",        true),
            ("content-security-policy",   "CSP",         true),
            ("x-frame-options",           "X-Frame",     true),
            ("x-content-type-options",    "XCTO",        true),
            ("referrer-policy",           "Ref-Policy",  false),
            ("permissions-policy",        "Perm-Policy", false),
        ];
        let mut missing_critical: Vec<String> = Vec::new();
        let mut lines = vec![
            format!("**HTTP Header Analysis** `{}`\n", url),
            format!("  Status  : {}", resp.status),
            format!("  Server  : {}", resp.headers.get("server").map(|s| s.as_str()).unwrap_or("hidden")),
            format!("  Powered : {}", resp.headers.get("x-powered-by").map(|s| s.as_str()).unwrap_or("hidden")),
            String::new(),
            "  Security Headers:".to_string(),
        ];
        for (hdr, label, critical) in &sec_hdrs {
            let val = resp.headers.get(*hdr);
            let present = val.is_some();
            let flag = if present { "✓" } else if *critical { "✗ [CRITICAL]" } else { "✗ [INFO]" };
            let display = val.map(|v| &v[..v.len().min(80)]).unwrap_or("absent");
            lines.push(format!("    {} {:<15} {}", flag, label, display));
            if !present && *critical { missing_critical.push(label.to_string()); }
        }
        if !missing_critical.is_empty() {
            lines.push(format!("\n  [CRITICAL] Missing: {}", missing_critical.join(", ")));
        }
        let mut tags = vec!["http_headers"];
        if !missing_critical.is_empty() { tags.push("missing_headers"); }
        SkillResult::ok(self.name(), lines.join("\n"), tags)
    }
}

struct NetworkReconSkill;
impl Skill for NetworkReconSkill {
    fn name(&self)             -> &'static str { "network_recon" }
    fn description(&self)      -> &'static str { "Network recon: CIDR host discovery, service sweep" }
    fn usage(&self)            -> &'static str { "network_recon <cidr_or_host>  e.g. 192.168.1.0/24" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["network recon","host discovery","cidr scan","topology"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let target = args.trim();
        if target.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        // Generate IP list from CIDR or single host
        let hosts: Vec<String> = if target.contains('/') {
            let parts: Vec<&str> = target.splitn(2, '/').collect();
            let prefix: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(24);
            let base: u32 = parts[0].parse::<Ipv4Addr>().map(|ip| u32::from(ip)).unwrap_or(0);
            let mask = !((1u32 << (32 - prefix)) - 1);
            let network = base & mask;
            let count   = (1u32 << (32 - prefix)).min(64);
            (1..count - 1).map(|i| {
                let ip = network + i;
                format!("{}.{}.{}.{}", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
            }).collect()
        } else {
            use std::net::ToSocketAddrs;
            match format!("{}:0", target).to_socket_addrs() {
                Ok(a) => a.map(|s| s.ip().to_string()).collect::<HashSet<_>>().into_iter().collect(),
                Err(e) => return SkillResult::err(self.name(), format!("Cannot resolve: {}", e)),
            }
        };
        let probe_ports = vec![22u16, 80, 443, 445, 3389];
        let mut live: Vec<(String, Vec<u16>)> = Vec::new();
        use std::thread;
        let handles: Vec<_> = hosts.iter().map(|ip| {
            let ip_str = ip.clone();
            let pp     = probe_ports.clone();
            thread::spawn(move || {
                let open: Vec<u16> = pp.iter().filter(|&&p| tcp_probe(&ip_str, p, 800).0).copied().collect();
                if open.is_empty() { None } else { Some((ip_str, open)) }
            })
        }).collect();
        for h in handles {
            if let Ok(Some(result)) = h.join() { live.push(result); }
        }
        let mut lines = vec![format!("**Network Recon** `{}` — {} host(s) scanned\n", target, hosts.len())];
        if live.is_empty() { lines.push("  No live hosts discovered.".to_string()); }
        else {
            lines.push(format!("  **Live Hosts ({}):**", live.len()));
            for (ip, ports) in &live {
                let svcs: Vec<String> = ports.iter().map(|&p| format!("{}({})", well_known_service(p), p)).collect();
                lines.push(format!("    {:<17}  {}", ip, svcs.join(", ")));
            }
            let risky = live.iter().any(|(_, ports)| ports.iter().any(|&p| p == 23 || p == 21 || p == 3389));
            lines.push(format!("\n  Risk: [{}]", if risky { "HIGH" } else { "MEDIUM" }));
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["network_recon", target])
    }
}

struct DnsSecuritySkill;
impl Skill for DnsSecuritySkill {
    fn name(&self)             -> &'static str { "dns_security" }
    fn description(&self)      -> &'static str { "DNS security: DNSSEC, zone transfer, SPF/DKIM/DMARC" }
    fn usage(&self)            -> &'static str { "dns_security <domain>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["dns security","dnssec","zone transfer","spf dkim dmarc","email security"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let domain = args.trim().to_lowercase();
        if domain.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let dig = |rtype: &str, target: &str| -> Vec<String> {
            Command::new("dig").args(["+short", rtype, target]).output().ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
                .unwrap_or_default()
        };
        let a_recs  = dig("A",   &domain);
        let ns_recs = dig("NS",  &domain);
        let mx_recs = dig("MX",  &domain);
        let txt_recs= dig("TXT", &domain);
        let dmarc_recs = dig("TXT", &format!("_dmarc.{}", domain));
        let dkim_recs  = dig("TXT", &format!("default._domainkey.{}", domain));
        let spf   = txt_recs.iter().any(|r| r.contains("v=spf1"));
        let dmarc = dmarc_recs.iter().any(|r| r.to_lowercase().contains("v=dmarc1"));
        let dkim  = dkim_recs.iter().any(|r| r.to_lowercase().contains("v=dkim1"));
        // Zone transfer
        let zt_vuln = ns_recs.first().map(|ns| {
            let ns_host = ns.trim_end_matches('.');
            Command::new("dig").args(["AXFR", &domain, &format!("@{}", ns_host)]).output()
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().count() > 5)
                .unwrap_or(false)
        }).unwrap_or(false);
        let mut lines = vec![format!("**DNS Security Analysis** `{}`\n", domain)];
        lines.push(format!("  A records  : {}", if a_recs.is_empty() { "none".to_string() } else { a_recs.join(", ") }));
        lines.push(format!("  MX records : {}", if mx_recs.is_empty() { "none".to_string() } else { mx_recs[..mx_recs.len().min(3)].join(", ") }));
        lines.push(format!("  NS records : {}", if ns_recs.is_empty() { "none".to_string() } else { ns_recs[..ns_recs.len().min(3)].join(", ") }));
        lines.push(String::new());
        lines.push("  Email Security:".to_string());
        lines.push(format!("    SPF   : {}", if spf   { "✓ present" } else { "✗ [WARN] missing" }));
        lines.push(format!("    DMARC : {}", if dmarc { "✓ present" } else { "✗ [WARN] missing" }));
        lines.push(format!("    DKIM  : {}", if dkim  { "✓ present" } else { "⚠ default selector not found" }));
        lines.push(String::new());
        lines.push(format!("  Zone Transfer : {}", if zt_vuln { "[CRITICAL] ALLOWED — data exposed" } else { "✓ Restricted" }));
        let risk = if zt_vuln { "HIGH" } else if !spf || !dmarc { "MEDIUM" } else { "LOW" };
        lines.push(format!("  Risk Level    : [{}]", risk));
        let mut tags = vec!["dns_security", &domain as &str];
        if zt_vuln  { tags.push("zone_transfer"); }
        if !spf     { tags.push("missing_spf"); }
        SkillResult::ok(self.name(), lines.join("\n"), tags)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE SKILLS
// ═════════════════════════════════════════════════════════════════════════════

struct CveLookupSkill;
impl Skill for CveLookupSkill {
    fn name(&self)             -> &'static str { "cve_lookup" }
    fn description(&self)      -> &'static str { "CVE details from NVD/NIST public API (no key needed)" }
    fn usage(&self)            -> &'static str { "cve_lookup <CVE-YYYY-NNNNN>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["cve lookup","vulnerability details","check cve","nvd"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let cve_id = args.trim().to_uppercase();
        let re = Regex::new(r"CVE-\d{4}-\d+").unwrap();
        if !re.is_match(&cve_id) { return SkillResult::err(self.name(), format!("Invalid CVE format. {}", self.usage())); }
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
        let resp = match http_get(&url, &[]) { Ok(r) => r, Err(e) => return SkillResult::err(self.name(), e) };
        let body = &resp.body;
        let desc_re  = Regex::new(r#""lang"\s*:\s*"en"\s*,\s*"value"\s*:\s*"([^"]{0,400})""#).unwrap();
        let score_re = Regex::new(r#""baseScore"\s*:\s*([\d.]+)"#).unwrap();
        let sev_re   = Regex::new(r#""baseSeverity"\s*:\s*"([^"]+)""#).unwrap();
        let desc  = desc_re.captures(body).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("No description");
        let score = score_re.captures(body).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("N/A");
        let sev   = sev_re.captures(body).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("N/A");
        let score_f: f64 = score.parse().unwrap_or(0.0);
        let tag = if score_f >= 9.0 { "[CRITICAL]" } else if score_f >= 7.0 { "[HIGH]" } else if score_f >= 4.0 { "[MEDIUM]" } else { "[LOW]" };
        let out = format!("**CVE** `{}` {}\n\n  CVSS Score  : {} ({})\n  Description : {}", cve_id, tag, score, sev, &desc[..desc.len().min(400)]);
        SkillResult::ok(self.name(), out, vec!["cve", &cve_id, &sev.to_lowercase()])
    }
}

struct IpReputationSkill;
impl Skill for IpReputationSkill {
    fn name(&self)             -> &'static str { "ip_reputation" }
    fn description(&self)      -> &'static str { "IP reputation via AbuseIPDB + DNSBL (set ABUSEIPDB_API_KEY)" }
    fn usage(&self)            -> &'static str { "ip_reputation <ip_address>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["ip reputation","is this ip malicious","check ip","ip abuse"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let ip = args.trim();
        if ip.parse::<Ipv4Addr>().is_err() { return SkillResult::err(self.name(), format!("Invalid IP: {}", ip)); }
        let mut lines = vec![format!("**IP Reputation** `{}`\n", ip)];
        // AbuseIPDB
        if let Ok(api_key) = env::var("ABUSEIPDB_API_KEY") {
            let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90", ip);
            match http_get(&url, &[("Key", &api_key), ("Accept","application/json")]) {
                Ok(resp) => {
                    let conf_re = Regex::new(r#""abuseConfidenceScore"\s*:\s*(\d+)"#).unwrap();
                    let rpt_re  = Regex::new(r#""totalReports"\s*:\s*(\d+)"#).unwrap();
                    let ctry_re = Regex::new(r#""countryCode"\s*:\s*"([^"]+)""#).unwrap();
                    let conf: u32 = conf_re.captures(&resp.body).and_then(|c| c[1].parse().ok()).unwrap_or(0);
                    let rpts = rpt_re.captures(&resp.body).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("0");
                    let ctry = ctry_re.captures(&resp.body).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("??");
                    let tag = if conf >= 75 { "[CRITICAL]" } else if conf >= 25 { "[WARN]" } else { "[CLEAN]" };
                    lines.push(format!("  AbuseIPDB: {} confidence={}%  reports={}  country={}", tag, conf, rpts, ctry));
                }
                Err(e) => lines.push(format!("  AbuseIPDB: error ({})", e)),
            }
        } else {
            lines.push("  AbuseIPDB: set ABUSEIPDB_API_KEY for live scoring".to_string());
        }
        // DNSBL
        let octets: Vec<&str> = ip.split('.').collect();
        let rev = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
        let dnsbls = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"];
        let mut listed = Vec::new();
        for bl in &dnsbls {
            use std::net::ToSocketAddrs;
            if format!("{}.{}:0", rev, bl).to_socket_addrs().is_ok() { listed.push(*bl); }
        }
        if listed.is_empty() { lines.push(format!("  DNSBL: ✓ not listed on {} checked blocklists", dnsbls.len())); }
        else { lines.push(format!("  [CRITICAL] DNSBL listed on: {}", listed.join(", "))); }
        let mut tags = vec!["ip_reputation", ip];
        if !listed.is_empty() { tags.push("blacklisted"); }
        SkillResult::ok(self.name(), lines.join("\n"), tags)
    }
}

struct HashLookupSkill;
impl Skill for HashLookupSkill {
    fn name(&self)             -> &'static str { "hash_lookup" }
    fn description(&self)      -> &'static str { "Hash a string/file (MD5/SHA1/SHA256) + optional VirusTotal" }
    fn usage(&self)            -> &'static str { "hash_lookup <text_or_filepath> [md5|sha1|sha256]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["hash lookup","virustotal","file hash","malware hash","check hash"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let target = args.trim().split_whitespace().next().unwrap_or(args.trim());
        let data: Vec<u8> = std::fs::read(target).unwrap_or_else(|_| target.as_bytes().to_vec());
        use md5::Digest;
        let md5    = format!("{:x}", <md5::Md5 as md5::Digest>::digest(&data));
        let sha256 = {
            let mut h = sha2::Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        };
        let mut lines = vec![
            "**Hash Lookup**\n".to_string(),
            format!("  MD5    : {}", md5),
            format!("  SHA256 : {}", sha256),
        ];
        if let Ok(vt_key) = env::var("VIRUSTOTAL_API_KEY") {
            let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
            match http_get(&url, &[("x-apikey", &vt_key)]) {
                Ok(resp) if resp.status == 404 => lines.push("  VT     : not found in VirusTotal database".to_string()),
                Ok(resp) if resp.status == 200 => {
                    let mal_re = Regex::new(r#""malicious"\s*:\s*(\d+)"#).unwrap();
                    let mal: u32 = mal_re.captures(&resp.body).and_then(|c| c[1].parse().ok()).unwrap_or(0);
                    let tag = if mal > 5 { "[CRITICAL]" } else if mal > 0 { "[WARN]" } else { "[CLEAN]" };
                    lines.push(format!("  VT     : {} {} engines flagged malicious", tag, mal));
                }
                _ => lines.push("  VT     : lookup unavailable".to_string()),
            }
        } else {
            lines.push("  VT     : set VIRUSTOTAL_API_KEY for live lookup".to_string());
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["hash", &sha256[..16]])
    }
}

struct IocExtractorSkill;
impl Skill for IocExtractorSkill {
    fn name(&self)             -> &'static str { "ioc_extractor" }
    fn description(&self)      -> &'static str { "Extract IOCs: IPs, domains, hashes, CVEs, emails, URLs" }
    fn usage(&self)            -> &'static str { "ioc_extractor <text>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["extract ioc","find indicators","ioc extract","parse indicators"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let patterns: Vec<(&str, Regex)> = vec![
            ("IPv4",   Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b").unwrap()),
            ("URL",    Regex::new(r"https?://[^\s\"'<>]{8,200}").unwrap()),
            ("Email",  Regex::new(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b").unwrap()),
            ("MD5",    Regex::new(r"\b[0-9a-fA-F]{32}\b").unwrap()),
            ("SHA256", Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap()),
            ("CVE",    Regex::new(r"(?i)\bCVE-\d{4}-\d{4,}\b").unwrap()),
        ];
        let mut results: Vec<(String, Vec<String>)> = Vec::new();
        for (label, re) in &patterns {
            let found: HashSet<String> = re.find_iter(args).map(|m| m.as_str().to_string()).collect();
            if !found.is_empty() {
                let mut sorted: Vec<String> = found.into_iter().collect();
                sorted.sort();
                results.push((label.to_string(), sorted));
            }
        }
        if results.is_empty() { return SkillResult::ok(self.name(), "No IOCs found in provided text.".to_string(), vec![]); }
        let total: usize = results.iter().map(|(_, v)| v.len()).sum();
        let mut lines = vec![format!("**IOC Extraction** — {} indicators found\n", total)];
        for (typ, items) in &results {
            lines.push(format!("  {} ({}):", typ, items.len()));
            items.iter().take(20).for_each(|i| lines.push(format!("    {}", i)));
            if items.len() > 20 { lines.push(format!("    … and {} more", items.len() - 20)); }
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["ioc_extraction", &format!("count:{}", total)])
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ANALYSIS SKILLS
// ═════════════════════════════════════════════════════════════════════════════

struct LogAnalyzerSkill;
impl Skill for LogAnalyzerSkill {
    fn name(&self)             -> &'static str { "log_analyzer" }
    fn description(&self)      -> &'static str { "Deep log analysis: brute-force, SQLi, XSS, recon patterns" }
    fn usage(&self)            -> &'static str { "log_analyzer <log text>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["analyze log","parse log","check logs","log analysis","siem"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let ip_re   = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        let fail_re = Regex::new(r"(?i)(FAILED_LOGIN|authentication failure|invalid password)").unwrap();
        let sqli_re = Regex::new(r"(?i)(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|xp_cmdshell)").unwrap();
        let xss_re  = Regex::new(r"(?i)(<script|javascript:|onerror=)").unwrap();
        let path_re = Regex::new(r"(?i)(\.\./|/etc/passwd)").unwrap();
        let ts_re   = Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}").unwrap();
        let lines: Vec<&str> = args.lines().collect();
        let ips: HashSet<String> = ip_re.find_iter(args).map(|m| m.as_str().to_string()).collect();
        let ts: Vec<String> = ts_re.find_iter(args).map(|m| m.as_str().to_string()).collect::<HashSet<_>>()
            .into_iter().collect::<Vec<_>>().into_iter().collect();
        let mut failures: HashMap<String, u32> = HashMap::new();
        let mut sqli_lines = Vec::new(); let mut xss_lines = Vec::new(); let mut path_lines = Vec::new();
        for line in &lines {
            if fail_re.is_match(line) { for m in ip_re.find_iter(line) { *failures.entry(m.as_str().to_string()).or_insert(0) += 1; } }
            if sqli_re.is_match(line) { sqli_lines.push(*line); }
            if xss_re.is_match(line)  { xss_lines.push(*line); }
            if path_re.is_match(line) { path_lines.push(*line); }
        }
        let mut out_lines = vec![format!("**Log Analysis** — {} lines, {} unique IPs\n", lines.len(), ips.len())];
        if !ts.is_empty() {
            let mut sorted_ts = ts.clone(); sorted_ts.sort();
            out_lines.push(format!("  Time range: {} → {}", sorted_ts.first().unwrap(), sorted_ts.last().unwrap()));
        }
        let mut findings = Vec::new();
        for (ip, cnt) in &failures {
            let tag = if *cnt >= 5 { "[CRITICAL]" } else { "[WARN]" };
            findings.push(format!("{} Brute-force: {} failures from {}", tag, cnt, ip));
        }
        if !sqli_lines.is_empty()  { findings.push(format!("[CRITICAL] SQL Injection: {} lines", sqli_lines.len())); }
        if !xss_lines.is_empty()   { findings.push(format!("[CRITICAL] XSS attempts: {} lines", xss_lines.len())); }
        if !path_lines.is_empty()  { findings.push(format!("[HIGH] Path traversal: {} lines", path_lines.len())); }
        if findings.is_empty() { out_lines.push("  ✓ No anomalies detected".to_string()); }
        else { out_lines.push("  **Findings:**".to_string()); findings.iter().for_each(|f| out_lines.push(format!("    {}", f))); }
        let mut tags = vec!["log_analysis"];
        if !sqli_lines.is_empty() { tags.push("sql_injection"); }
        if !xss_lines.is_empty()  { tags.push("xss"); }
        if !failures.is_empty()   { tags.push("brute_force"); }
        SkillResult::ok(self.name(), out_lines.join("\n"), tags)
    }
}

struct VulnerabilityScorerSkill;
impl Skill for VulnerabilityScorerSkill {
    fn name(&self)             -> &'static str { "vulnerability_scorer" }
    fn description(&self)      -> &'static str { "CVSS v3.1 scoring and OWASP risk rating via AI" }
    fn usage(&self)            -> &'static str { "vulnerability_scorer <finding description>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["score vulnerability","cvss score","risk rating","assess vulnerability"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let prompt = r#"You are a CVSS v3.1 expert. Return ONLY JSON: {"cvss_score":7.5,"cvss_severity":"HIGH","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","owasp_category":"A03:2021","attack_vector":"Network","confidentiality_impact":"High","integrity_impact":"None","availability_impact":"None","remediation_priority":"Critical","recommended_fix":"Parameterise all queries"}"#;
        match call_deepseek(prompt, &[memory_manager::Message { role:"user".to_string(), content:format!("Score: {}", &args[..args.len().min(2000)]) }], 0.1) {
            Err(e) => SkillResult::err(self.name(), e),
            Ok(raw) => {
                let json_re = Regex::new(r"\{[\s\S]+\}").unwrap();
                let extract = |key: &str| -> String {
                    Regex::new(&format!(r#""{}":\s*"?([^",\}}]+)"?"#, key)).ok()
                        .and_then(|r| r.captures(&raw))
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().trim().to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                };
                let out = format!(
                    "**Vulnerability Score**\n\n  CVSS Score  : {} ({})\n  CVSS Vector : {}\n  OWASP       : {}\n  C/I/A       : {}/{}/{}\n  Priority    : {}\n  Fix         : {}",
                    extract("cvss_score"), extract("cvss_severity"), extract("cvss_vector"),
                    extract("owasp_category"), extract("confidentiality_impact"),
                    extract("integrity_impact"), extract("availability_impact"),
                    extract("remediation_priority"), extract("recommended_fix")
                );
                SkillResult::ok(self.name(), out, vec!["vuln_score"])
            }
        }
    }
}

struct VulnerabilityAssessmentSkill;
impl Skill for VulnerabilityAssessmentSkill {
    fn name(&self)             -> &'static str { "vulnerability_assessment" }
    fn description(&self)      -> &'static str { "Full assessment: port scan + service fingerprint + NVD CVE correlation" }
    fn usage(&self)            -> &'static str { "vulnerability_assessment <host>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["vulnerability assessment","full scan","assess target","pentest"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let host = args.trim();
        if host.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let common_ports = vec![21u16,22,23,25,53,80,110,143,389,443,445,3306,3389,5432,6379,8080,8443,27017];
        let open_ports: Vec<(u16, String)> = {
            use std::thread;
            let h = host.to_string();
            let handles: Vec<_> = common_ports.iter().map(|&port| { let hh=h.clone(); thread::spawn(move || { let (open,banner)=tcp_probe(&hh,port,1200); (port,open,banner) }) }).collect();
            handles.into_iter().filter_map(|h| h.join().ok()).filter(|(_,open,_)| *open).map(|(p,_,b)| (p,b)).collect()
        };
        let mut all_cves: Vec<String> = Vec::new();
        let mut seen_svcs = HashSet::new();
        for (port, _) in open_ports.iter().take(5) {
            let svc = well_known_service(*port);
            if svc == "unknown" || seen_svcs.contains(svc) { continue; }
            seen_svcs.insert(svc);
            let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=3", svc);
            if let Ok(resp) = http_get(&url, &[]) {
                let re = Regex::new(r#""id"\s*:\s*"(CVE-[^"]+)""#).unwrap();
                for cap in re.captures_iter(&resp.body) { if all_cves.len() < 8 { all_cves.push(format!("{} ({})", &cap[1], svc)); } }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let risky_open = open_ports.iter().any(|(p,_)| *p == 23 || *p == 21);
        let risk = if risky_open { "CRITICAL" } else if !all_cves.is_empty() { "HIGH" } else if open_ports.is_empty() { "LOW" } else { "MEDIUM" };
        let mut lines = vec![
            format!("**Vulnerability Assessment** `{}`\n", host),
            format!("  Risk Level  : [{}]", risk),
            format!("  Open Ports  : {}", open_ports.len()),
            format!("  CVEs Found  : {}", all_cves.len()),
            String::new(),
        ];
        if !open_ports.is_empty() {
            lines.push("  **Open Ports:**".to_string());
            for (port, banner) in &open_ports { lines.push(format!("    {:5}/tcp  {:<12}{}", port, well_known_service(*port), if banner.is_empty() { String::new() } else { format!(" — `{}`", banner) })); }
        }
        if !all_cves.is_empty() {
            lines.push(String::new()); lines.push("  **Related CVEs (NVD):**".to_string());
            all_cves.iter().for_each(|c| lines.push(format!("    {}", c)));
        }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["vuln_assessment", host, risk.to_lowercase().leak()])
    }
}

struct WebAppScannerSkill;
impl Skill for WebAppScannerSkill {
    fn name(&self)             -> &'static str { "web_app_scanner" }
    fn description(&self)      -> &'static str { "OWASP Top 10 active scan: SQLi probe, XSS probe, sensitive paths, headers" }
    fn usage(&self)            -> &'static str { "web_app_scanner <url> [auth_header]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["web app scan","owasp scan","web scan","xss scan","sqli scan"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() || parts[0].is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let url = if parts[0].starts_with("http") { parts[0].to_string() } else { format!("https://{}", parts[0]) };
        let auth: Vec<(&str,&str)> = if parts.len() > 1 { vec![("Authorization", parts[1])] } else { vec![] };
        let base = match http_head(&url, &auth) { Ok(r) => r, Err(e) => return SkillResult::err(self.name(), e) };
        let mut findings = Vec::new();
        // Security headers
        let sec = ["strict-transport-security","content-security-policy","x-frame-options","x-content-type-options"];
        let missing: Vec<&str> = sec.iter().filter(|h| !base.headers.contains_key(**h)).copied().collect();
        if !missing.is_empty() { findings.push(format!("[MEDIUM] Missing security headers: {}", missing.join(", "))); }
        // Info disclosure
        if let Some(s) = base.headers.get("server") { findings.push(format!("[LOW] Server header: {}", s)); }
        if let Some(p) = base.headers.get("x-powered-by") { findings.push(format!("[LOW] X-Powered-By: {}", p)); }
        // SQLi probe
        let sqli_url = format!("{}?id=%27%20OR%20%271%27%3D%271", url);
        if let Ok(r) = http_get(&sqli_url, &auth) {
            let body_low = r.body.to_lowercase();
            if ["sql syntax","mysql_fetch","ora-","sqlstate"].iter().any(|s| body_low.contains(s)) {
                findings.push("[CRITICAL] SQLi: error returned for injection payload".to_string());
            }
        }
        // XSS probe
        let xss_url = format!("{}?q=%3Cscript%3Ealert(1)%3C/script%3E", url);
        if let Ok(r) = http_get(&xss_url, &auth) {
            if r.body.contains("<script>alert(1)</script>") { findings.push("[HIGH] XSS: payload reflected in response".to_string()); }
        }
        // Sensitive paths
        for path in &["/.env","/.git/HEAD","/phpinfo.php","/admin","/actuator/env","/api/v1/users"] {
            if let Ok(r) = http_get(&format!("{}{}", url, path), &auth) {
                if r.status == 200 {
                    let sev = if path.contains(".env") || path.contains("git") { "CRITICAL" } else { "MEDIUM" };
                    findings.push(format!("[{}] HTTP 200 at {}", sev, path));
                }
            }
        }
        let risk = if findings.iter().any(|f| f.contains("[CRITICAL]")) { "CRITICAL" }
                   else if findings.iter().any(|f| f.contains("[HIGH]")) { "HIGH" }
                   else if findings.is_empty() { "LOW" } else { "MEDIUM" };
        let mut lines = vec![
            format!("**Web App Scanner** `{}`\n", url),
            format!("  Baseline   : HTTP {}", base.status),
            format!("  Risk Level : [{}]", risk),
            format!("  Findings   : {}", findings.len()),
            String::new(),
        ];
        if findings.is_empty() { lines.push("  ✓ No critical vulnerabilities detected".to_string()); }
        else { lines.push("  **Findings:**".to_string()); findings.iter().for_each(|f| lines.push(format!("    {}", f))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["web_app_scan"])
    }
}

struct ApiSecurityAuditSkill;
impl Skill for ApiSecurityAuditSkill {
    fn name(&self)             -> &'static str { "api_security_audit" }
    fn description(&self)      -> &'static str { "API security: auth check, rate limiting, CORS, endpoint discovery" }
    fn usage(&self)            -> &'static str { "api_security_audit <base_url> [bearer_token]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["api security","api audit","api scan","rest api"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let base = if parts[0].starts_with("http") { parts[0].to_string() } else { format!("https://{}",parts[0]) };
        let auth_hdr: Vec<(&str,String)> = if parts.len()>1 { vec![("Authorization",format!("Bearer {}",parts[1]))] } else { vec![] };
        let auth_ref: Vec<(&str,&str)>   = auth_hdr.iter().map(|(k,v)| (*k,v.as_str())).collect();
        let resp = match http_get(&base, &auth_ref) { Ok(r) => r, Err(e) => return SkillResult::err(self.name(), e) };
        let mut findings = Vec::new();
        // CORS
        if resp.headers.get("access-control-allow-origin").map(|v| v=="*").unwrap_or(false) { findings.push("[HIGH] CORS: Access-Control-Allow-Origin: *".to_string()); }
        // Rate limiting
        let rl = resp.headers.keys().any(|k| k.contains("ratelimit")||k.contains("rate-limit")||k.contains("retry-after"));
        if !rl { findings.push("[MEDIUM] No rate-limiting headers detected".to_string()); }
        // Sensitive endpoints
        let sens_paths = vec!["/users","/admin","/swagger.json","/openapi.json","/.well-known/openid-configuration","/actuator","/actuator/env","/graphql","/api/v1/users"];
        for path in &sens_paths {
            if let Ok(r) = http_get(&format!("{}{}",base,path), &auth_ref) {
                if r.status==200 || r.status==201 {
                    let sev = if path.contains("actuator")||path.contains("admin") {"CRITICAL"} else {"MEDIUM"};
                    findings.push(format!("[{}] HTTP {} at {}", sev, r.status, path));
                }
            }
        }
        if let Some(s) = resp.headers.get("server") { findings.push(format!("[LOW] Server: {}", s)); }
        let risk = if findings.iter().any(|f|f.contains("CRITICAL")){"CRITICAL"}else if findings.iter().any(|f|f.contains("HIGH")){"HIGH"}else if findings.is_empty(){"LOW"}else{"MEDIUM"};
        let mut lines = vec![format!("**API Security Audit** `{}`\n", base), format!("  Baseline   : HTTP {}", resp.status), format!("  Risk Level : [{}]", risk), format!("  Issues     : {}", findings.len()), String::new()];
        if findings.is_empty() { lines.push("  ✓ No critical API issues detected".to_string()); }
        else { lines.push("  **Findings:**".to_string()); findings.iter().for_each(|f| lines.push(format!("    {}",f))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["api_security"])
    }
}

struct FirewallAuditorSkill;
impl Skill for FirewallAuditorSkill {
    fn name(&self)             -> &'static str { "firewall_auditor" }
    fn description(&self)      -> &'static str { "Firewall rules audit: parse iptables/nftables, detect over-permissive policies" }
    fn usage(&self)            -> &'static str { "firewall_auditor <paste iptables rules OR localhost>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["firewall audit","firewall rules","iptables","nftables"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let rules = if args.trim() == "localhost" {
            match Command::new("iptables").args(["-S"]).output() {
                Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                Err(_) => return SkillResult::err(self.name(), "iptables not available; paste rules directly"),
            }
        } else { args.trim().to_string() };
        let danger: Vec<(&str, &str, &str)> = vec![
            (r"-s 0\.0\.0\.0/0.*--dport 22",   "CRITICAL","SSH open to 0.0.0.0/0"),
            (r"-s 0\.0\.0\.0/0.*--dport 3389",  "CRITICAL","RDP open to 0.0.0.0/0"),
            (r"-s 0\.0\.0\.0/0.*--dport 23",    "CRITICAL","Telnet open to 0.0.0.0/0"),
            (r"-A FORWARD -j ACCEPT",            "HIGH",   "Unrestricted forwarding"),
            (r"(?i)policy ACCEPT",               "MEDIUM", "Default ACCEPT policy"),
            (r"--dport 445.*-j ACCEPT",          "HIGH",   "SMB/445 exposed"),
        ];
        let mut findings = Vec::new();
        for (pat, sev, desc) in &danger {
            if let Ok(re) = Regex::new(pat) { if rules.lines().any(|l| re.is_match(l)) { findings.push((*sev, *desc)); } }
        }
        let egress = rules.lines().any(|l| l.contains("OUTPUT") && (l.contains("DROP") || l.contains("REJECT")));
        if !egress { findings.push(("MEDIUM","No egress DROP rules — unrestricted outbound")); }
        let risk = if findings.iter().any(|f|f.0=="CRITICAL"){"CRITICAL"}else if findings.iter().any(|f|f.0=="HIGH"){"HIGH"}else if findings.is_empty(){"LOW"}else{"MEDIUM"};
        let accepts = rules.lines().filter(|l|l.contains("-j ACCEPT")).count();
        let drops   = rules.lines().filter(|l|l.contains("-j DROP")||l.contains("-j REJECT")).count();
        let mut lines = vec![format!("**Firewall Rules Audit**\n"), format!("  Rules : {}  ACCEPT: {}  DROP: {}", rules.lines().count(), accepts, drops), format!("  Risk Level : [{}]\n", risk)];
        if findings.is_empty() { lines.push("  ✓ No obvious over-permissive rules".to_string()); }
        else { lines.push("  **Findings:**".to_string()); findings.iter().for_each(|(s,d)| lines.push(format!("    [{:<8}] {}", s, d))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["firewall_audit"])
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLOUD / CONTAINER / AUTH SKILLS
// ═════════════════════════════════════════════════════════════════════════════

struct CloudPostureSkill;
impl Skill for CloudPostureSkill {
    fn name(&self)             -> &'static str { "cloud_posture" }
    fn description(&self)      -> &'static str { "Cloud security posture: AWS public bucket probe, security groups" }
    fn usage(&self)            -> &'static str { "cloud_posture <account_id_or_name> [aws|gcp|azure]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["cloud posture","cloud security","aws security","s3 bucket","iam review"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let target   = parts[0];
        let provider = parts.get(1).copied().unwrap_or("aws");
        let mut lines = vec![format!("**Cloud Security Posture** `{}` ({})\n", target, provider.to_uppercase())];
        let mut findings = Vec::new();
        if provider == "aws" {
            // Try AWS CLI first
            match Command::new("aws").args(["s3api","list-buckets","--query","Buckets[].Name","--output","json"]).output() {
                Ok(out) if out.status.success() => {
                    let json = String::from_utf8_lossy(&out.stdout);
                    let name_re = Regex::new(r#""([^"]+)""#).unwrap();
                    for cap in name_re.captures_iter(&json) {
                        let bucket = &cap[1];
                        let url = format!("https://{}.s3.amazonaws.com/", bucket);
                        if let Ok(r) = http_get(&url, &[]) {
                            if r.status == 200 { findings.push(format!("[CRITICAL] Public S3 bucket: {}", bucket)); }
                            else if r.status == 403 { lines.push(format!("  Bucket {}: private (403)", bucket)); }
                        }
                    }
                }
                _ => {
                    lines.push("  AWS CLI not available — probing common bucket patterns".to_string());
                    for suffix in &["", "-public", "-data", "-backup", "-dev", "-prod"] {
                        let url = format!("https://{}{}.s3.amazonaws.com/", target, suffix);
                        if let Ok(r) = http_get(&url, &[]) {
                            match r.status {
                                200 => findings.push(format!("[CRITICAL] Public S3 bucket: {}{}", target, suffix)),
                                403 => lines.push(format!("  {}{}: exists but private (403)", target, suffix)),
                                _ => {}
                            }
                        }
                    }
                }
            }
        } else {
            lines.push(format!("  Install {} CLI and configure credentials for full audit", provider.to_uppercase()));
            findings.push(format!("[INFO] Manual {} CLI checks required", provider.to_uppercase()));
        }
        let risk = if findings.iter().any(|f|f.contains("CRITICAL")){"CRITICAL"}else if findings.is_empty(){"INFO"}else{"MEDIUM"};
        lines.push(format!("\n  **Risk Level: [{}]**\n", risk));
        if findings.is_empty() { lines.push("  ✓ No public exposures detected".to_string()); }
        else { lines.push("  **Findings:**".to_string()); findings.iter().for_each(|f|lines.push(format!("    {}",f))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["cloud_posture", provider, target])
    }
}

struct ContainerScannerSkill;
impl Skill for ContainerScannerSkill {
    fn name(&self)             -> &'static str { "container_scanner" }
    fn description(&self)      -> &'static str { "Container security: Docker inspect, Dockerfile audit, secret scan" }
    fn usage(&self)            -> &'static str { "container_scanner <image:tag OR Dockerfile_path>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["container scan","docker scan","image scan","dockerfile"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let target = args.trim();
        if target.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let mut lines = vec![format!("**Container Security Scan** `{}`\n", target)];
        let mut findings: Vec<(String,String)> = Vec::new();
        // Dockerfile check
        let df_path = std::path::Path::new(target);
        if df_path.exists() {
            match std::fs::read_to_string(df_path) {
                Ok(content) => {
                    let checks: Vec<(&str,&str,&str)> = vec![
                        (r"(?im)^FROM.*:latest",      "medium",   "Using :latest tag — unpinned"),
                        (r"(?im)^USER\s+root",         "critical", "Running as root user"),
                        (r"(?im)chmod\s+777",          "high",     "chmod 777 — world-writable"),
                        (r"(?im)--privileged",         "critical", "--privileged flag"),
                        (r"(?im)(password|api_key|secret)\s*=\s*\S{4,}", "critical", "Potential secret in Dockerfile"),
                        (r"(?im)^ADD\s+http",          "high",     "ADD from remote URL (no checksum)"),
                    ];
                    for (pat, sev, desc) in &checks {
                        if Regex::new(pat).map(|r| r.is_match(&content)).unwrap_or(false) {
                            findings.push((sev.to_string(), desc.to_string()));
                        }
                    }
                }
                Err(e) => return SkillResult::err(self.name(), format!("Cannot read Dockerfile: {}", e)),
            }
        } else {
            // Try docker inspect
            match Command::new("docker").args(["inspect", target]).output() {
                Ok(out) if out.status.success() => {
                    let json = String::from_utf8_lossy(&out.stdout);
                    if json.contains(r#""User": """#) || json.contains(r#""User":"""#) { findings.push(("critical".to_string(),"Container runs as root".to_string())); }
                    if json.contains(r#""Privileged": true"#) { findings.push(("critical".to_string(),"--privileged mode enabled".to_string())); }
                    if Regex::new(r"(?i)(PASSWORD|API_KEY|SECRET)\s*=").map(|r|r.is_match(&json)).unwrap_or(false) { findings.push(("critical".to_string(),"Secret in environment variables".to_string())); }
                }
                _ => {
                    let img_name = target.split(':').next().unwrap_or(target).split('/').last().unwrap_or(target);
                    lines.push(format!("  Docker not available — NVD CVE lookup for '{}'", img_name));
                    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=3", img_name);
                    if let Ok(resp) = http_get(&url, &[]) {
                        let re = Regex::new(r#""id"\s*:\s*"(CVE-[^"]+)""#).unwrap();
                        let mut cnt = 0;
                        for cap in re.captures_iter(&resp.body) { if cnt < 3 { findings.push(("medium".to_string(), format!("NVD: {} for '{}'", &cap[1], img_name))); cnt+=1; } }
                    }
                }
            }
        }
        let risk = if findings.iter().any(|f|f.0=="critical"){"CRITICAL"}else if findings.iter().any(|f|f.0=="high"){"HIGH"}else if findings.is_empty(){"LOW"}else{"MEDIUM"};
        lines.push(format!("  **Risk Level: [{}]**\n", risk));
        if findings.is_empty() { lines.push("  ✓ No critical container issues".to_string()); }
        else { lines.push("  **Findings:**".to_string()); findings.iter().for_each(|(s,d)|lines.push(format!("    [{:<8}] {}",s.to_uppercase(),d))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["container_scan"])
    }
}

struct PasswordAuditSkill;
impl Skill for PasswordAuditSkill {
    fn name(&self)             -> &'static str { "password_audit" }
    fn description(&self)      -> &'static str { "Password security: policy check, lockout probe, hash detection" }
    fn usage(&self)            -> &'static str { "password_audit <target_url_or_system> [policy_notes]" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["password audit","password security","brute force risk","auth policy"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
        if parts.is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let target = parts[0]; let policy = parts.get(1).copied().unwrap_or("");
        let mut lines = vec![format!("**Password Security Audit** `{}`\n", target)];
        let mut issues = Vec::new();
        // Hash detection
        if Regex::new(r"^[\$a-fA-F0-9]{32,}$").map(|r| r.is_match(target)).unwrap_or(false) {
            let algo = if target.starts_with("$2") { "bcrypt (strong)" }
                       else if target.starts_with("$1") { "MD5-crypt [WEAK]" }
                       else if target.len() == 32 { "MD5-plain [CRITICAL]" }
                       else { "unknown" };
            lines.push(format!("  Hash: {}", algo));
            if algo.contains("WEAK") || algo.contains("CRITICAL") { issues.push(format!("[CRITICAL] Weak hash: {}", algo)); }
        }
        // Transport
        if target.starts_with("http") {
            let https = target.starts_with("https");
            lines.push(format!("  Transport : {}", if https { "✓ HTTPS" } else { "[CRITICAL] HTTP — credentials in plaintext" }));
            if !https { issues.push("[CRITICAL] HTTP — credentials exposed in transit".to_string()); }
            // Lockout probe
            let weak_pwds = ["password","123456","admin","root","test"];
            let mut lockout_found = false;
            for (i, pwd) in weak_pwds.iter().enumerate() {
                let body = format!("username=admin&password={}", pwd);
                match ureq::post(target)
                    .set("Content-Type","application/x-www-form-urlencoded")
                    .set("User-Agent","OMNIKON-SecOps/1.0.2")
                    .timeout(Duration::from_secs(5))
                    .send_string(&body)
                {
                    Ok(resp) if resp.status() == 429 => {
                        lockout_found = true;
                        lines.push(format!("  Lockout   : ✓ Rate-limited after {} attempt(s)", i+1));
                        break;
                    }
                    _ => {}
                }
            }
            if !lockout_found { lines.push("  Lockout   : [CRITICAL] No lockout detected — brute-force risk".to_string()); issues.push("[CRITICAL] No account lockout".to_string()); }
        }
        if !policy.is_empty() { lines.push(format!("  Policy    : {}", policy)); }
        let risk = if issues.iter().any(|i|i.contains("CRITICAL")){"CRITICAL"}else if issues.is_empty(){"LOW"}else{"MEDIUM"};
        lines.push(format!("\n  **Risk Level: [{}]**", risk));
        if !issues.is_empty() { lines.push("\n  **Issues:**".to_string()); issues.iter().for_each(|i|lines.push(format!("    {}",i))); }
        SkillResult::ok(self.name(), lines.join("\n"), vec!["password_audit"])
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// UTILITY SKILLS
// ═════════════════════════════════════════════════════════════════════════════

struct SummarizerSkill;
impl Skill for SummarizerSkill {
    fn name(&self)             -> &'static str { "summarizer" }
    fn description(&self)      -> &'static str { "Summarize text using DeepSeek" }
    fn usage(&self)            -> &'static str { "summarizer <text>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["summarize","tldr","condense"] }
    fn run(&self, args: &str, _mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        match call_deepseek("Return only a concise summary, no preamble.",
            &[memory_manager::Message { role:"user".to_string(), content: format!("Summarize:\n{}", &args[..args.len().min(6000)]) }],
            0.3)
        {
            Ok(s)  => SkillResult::ok(self.name(), format!("**Summary:**\n{}", s), vec!["summary"]),
            Err(e) => SkillResult::err(self.name(), e),
        }
    }
}

struct MemoryWriterSkill;
impl Skill for MemoryWriterSkill {
    fn name(&self)             -> &'static str { "memory_writer" }
    fn description(&self)      -> &'static str { "Write a fact to long-term memory" }
    fn usage(&self)            -> &'static str { "memory_writer <text>" }
    fn trigger_patterns(&self) -> &'static [&'static str] { &["remember this","save to memory","note this"] }
    fn run(&self, args: &str, mm: &MemoryManager) -> SkillResult {
        if args.trim().is_empty() { return SkillResult::err(self.name(), format!("Usage: {}", self.usage())); }
        let e = mm.archive.store(args.trim(), "skill_memory_writer", vec!["fact".to_string()]);
        SkillResult::ok(self.name(), format!("✓ Stored → `{}`", e.id), vec![])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Skill Registry
// ─────────────────────────────────────────────────────────────────────────────

struct SkillRegistry {
    skills: Vec<Box<dyn Skill>>,
}

impl SkillRegistry {
    fn new() -> Self {
        Self {
            skills: vec![
                // NETWORK
                Box::new(PortScannerSkill), Box::new(DnsLookupSkill), Box::new(WhoisLookupSkill),
                Box::new(SslCertInspectorSkill), Box::new(HttpHeaderAnalyzerSkill),
                Box::new(NetworkReconSkill), Box::new(DnsSecuritySkill),
                // THREAT
                Box::new(CveLookupSkill), Box::new(IpReputationSkill),
                Box::new(HashLookupSkill), Box::new(IocExtractorSkill),
                // ANALYSIS
                Box::new(LogAnalyzerSkill), Box::new(VulnerabilityScorerSkill),
                Box::new(VulnerabilityAssessmentSkill), Box::new(WebAppScannerSkill),
                Box::new(ApiSecurityAuditSkill), Box::new(FirewallAuditorSkill),
                // CLOUD/CONTAINER/AUTH
                Box::new(CloudPostureSkill), Box::new(ContainerScannerSkill), Box::new(PasswordAuditSkill),
                // UTILITY
                Box::new(SummarizerSkill), Box::new(MemoryWriterSkill),
            ],
        }
    }
    fn get(&self, name: &str) -> Option<&dyn Skill> {
        self.skills.iter().find(|s| s.name() == name).map(|s| s.as_ref())
    }
    fn detect(&self, text: &str) -> Option<&dyn Skill> {
        let low = text.to_lowercase();
        self.skills.iter().find(|s| s.trigger_patterns().iter().any(|p| low.contains(p))).map(|s| s.as_ref())
    }
    fn names(&self) -> Vec<String> { self.skills.iter().map(|s| s.name().to_string()).collect() }
    fn help_text(&self) -> String {
        let sections = [
            ("NETWORK",   vec!["port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector","http_header_analyzer","network_recon","dns_security"]),
            ("THREAT",    vec!["cve_lookup","ip_reputation","hash_lookup","ioc_extractor"]),
            ("ANALYSIS",  vec!["log_analyzer","vulnerability_scorer","vulnerability_assessment","web_app_scanner","api_security_audit","firewall_auditor"]),
            ("CLOUD/CTR", vec!["cloud_posture","container_scanner"]),
            ("AUTH",      vec!["password_audit"]),
            ("UTILITY",   vec!["summarizer","memory_writer"]),
        ];
        let mut out = format!("**SecOps Skills v1.0.2 — {} skills:**\n\n", self.skills.len());
        for (sec, names) in &sections {
            out.push_str(&format!("  ── {} ──\n", sec));
            for n in names {
                if let Some(s) = self.get(n) {
                    out.push_str(&format!("  `{}` — {}\n    {}\n\n", s.name(), s.description(), s.usage()));
                }
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReAct Engine
// ─────────────────────────────────────────────────────────────────────────────

const MAX_ITER: u32 = 10;
const MAX_ERRS: u32 = 3;

fn parse_react(text: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let thought = Regex::new(r"Thought:\s*([\s\S]+?)(?=\nAction:|\nFinal Answer:|$)").ok()
        .and_then(|r| r.captures(text)).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string());
    let action  = Regex::new(r"Action:\s*(\w+)\s*(.*?)(?:\n|$)").ok()
        .and_then(|r| r.captures(text));
    let act     = action.as_ref().and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string());
    let act_arg = action.as_ref().and_then(|c| c.get(2)).map(|m| m.as_str().trim().to_string());
    let final_  = Regex::new(r"Final Answer:\s*([\s\S]+)").ok()
        .and_then(|r| r.captures(text)).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string());
    (thought, act, act_arg, final_)
}

fn react_system(mm: &MemoryManager, skills: &SkillRegistry) -> String {
    let base  = mm.context_for_query(&mm.working.reasoning().goal(), 3, 0.05);
    let skill_list = skills.skills.iter().map(|s| format!("  {}: {}", s.name(), s.description())).collect::<Vec<_>>().join("\n");
    format!("{}\n\n---\n\nYou are in ReAct mode.\nRespond: Thought: <reasoning>\\nAction: <skill> <args>\nOR: Thought: <reasoning>\\nFinal Answer: <answer>\n\nSkills:\n{}\nNever fabricate Observations. Check layer 2.5 trace.", base, skill_list)
}

fn exec_skill(name: &str, args: &str, mm: &MemoryManager, skills: &SkillRegistry) -> (String, bool) {
    match skills.get(name) {
        None => (format!("Unknown skill '{}'. Available: {}", name, skills.names().join(", ")), true),
        Some(skill) => {
            let r = skill.run(args, mm);
            if r.store_to_archive && r.success {
                mm.archive.store(
                    &format!("[{}] {}", r.skill, &r.output[..r.output.len().min(500)]),
                    &format!("skill_{}", r.skill),
                    r.archive_tags.clone(),
                );
            }
            (r.output, !r.success)
        }
    }
}

fn react_run(goal: &str, mm: &MemoryManager, skills: &SkillRegistry) -> String {
    mm.enable_react(goal);
    let rm = mm.working.reasoning();
    let mut errs = 0u32;
    eprintln!("\n🔄 ReAct: {}\n{}", goal, "─".repeat(60));
    for i in 1..=MAX_ITER {
        let t0  = Instant::now();
        let raw = match call_deepseek(&react_system(mm, skills), &mm.working.build_messages(), 0.3) {
            Ok(r) => r,
            Err(e) => { rm.record(TraceType::Observation, &format!("LLM error: {}", e), "", true, 0); errs += 1; if errs >= MAX_ERRS { break; } continue; }
        };
        let lat = t0.elapsed().as_millis() as u64;
        let (thought, action, act_args, final_) = parse_react(&raw);
        let t = thought.unwrap_or_else(|| raw[..raw.len().min(200)].to_string());
        rm.record(TraceType::Thought, &t, "", false, lat);
        eprintln!("  💭 [{}] {}", i, &t[..t.len().min(100)]);
        if let Some(ans) = final_ {
            rm.record(TraceType::Final, &ans, "", false, 0);
            mm.add_assistant_message(&ans);
            mm.finish_react(&ans);
            eprintln!("  ✅ Final: {}\n{}", &ans[..ans.len().min(160)], "─".repeat(60));
            return ans;
        }
        match action {
            None => { rm.record(TraceType::Observation, "No Action.", "", true, 0); mm.working.add_message("user", "No Action found. Respond: Thought: then Action: <skill> <args>"); errs += 1; }
            Some(act) => {
                let args_str = act_args.unwrap_or_default();
                rm.record(TraceType::Action, &format!("{} {}", act, args_str), &act, false, 0);
                eprintln!("  ⚡ [{}] Action: {} {}", i, act, &args_str[..args_str.len().min(70)]);
                let t1 = Instant::now();
                let (obs, is_err) = exec_skill(&act, &args_str, mm, skills);
                rm.record(TraceType::Observation, &obs, "", is_err, t1.elapsed().as_millis() as u64);
                eprintln!("  👁 [{}] {}", i, &obs[..obs.len().min(100)]);
                if is_err { errs += 1; }
                mm.working.add_message("user", &format!("Observation: {}", obs));
                mm.add_assistant_message(&raw);
            }
        }
        if errs >= MAX_ERRS { eprintln!("  ⚠ Max errors reached."); break; }
    }
    let fallback = format!("Loop ended. Last: {}", mm.working.reasoning().last_observation().chars().take(200).collect::<String>());
    mm.finish_react(&fallback);
    fallback
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent
// ─────────────────────────────────────────────────────────────────────────────

const BANNER: &str = r#"
╔══════════════════════════════════════════════════════════════════╗
║     OMNIKON SEC·OPS  —  AI Agent  v1.0.2  (Rust)               ║
║  LLM    : DeepSeek deepseek-chat                               ║
║  Skills : 22 real SecOps skills — UI-aligned, no mocks         ║
║────────────────────────────────────────────────────────────────║
║  /skills  /skill <name> <args>  /react <goal>  /react-step     ║
║  /react-status  /react-finish  /task  /step  /finish           ║
║  /status  /archive  /recall  /quit                             ║
╚══════════════════════════════════════════════════════════════════╝
"#;

struct Agent {
    mm:     MemoryManager,
    skills: SkillRegistry,
}

impl Agent {
    fn new(archive_path: &str) -> Self {
        let mm = MemoryManager::new(archive_path);
        let skills = SkillRegistry::new();
        let mut a = Self { mm, skills };
        a.configure_persona();
        a.configure_rules();
        a.seed_knowledge();
        log::info!("Agent v1.0.2 ready | {} | {} skills", archive_path, a.skills.skills.len());
        a
    }

    fn configure_persona(&mut self) {
        self.mm.working.with_character_mut(|c| {
            c.name = "OMNIKON SEC·OPS".to_string();
            c.tone = "precise and analytical".to_string();
            c.expertise = vec!["cybersecurity".to_string(),"network security".to_string(),"CVSS".to_string(),"OWASP".to_string(),"cloud security".to_string(),"ReAct".to_string()];
            c.personality = "Evidence-first. Chains skills for deep investigation. Uses ReAct for complex analysis.".to_string();
            c.response_format = "Markdown".to_string();
            c.constraints = vec![
                "Never reveal API keys or credentials.".to_string(),
                "[CRITICAL] prefix for CVSS≥7.0 or confirmed attacks.".to_string(),
                "In ReAct: Thought → Action → Observation always.".to_string(),
            ];
        });
    }

    fn configure_rules(&mut self) {
        let names = self.skills.names().join(", ");
        self.mm.add_system_rule("Respond only in English.");
        self.mm.add_system_rule(&format!("Skills ({}): {}", self.skills.skills.len(), names));
        self.mm.add_system_rule("Chain skills: dns_lookup → port_scanner → ssl_cert_inspector → http_header_analyzer | vulnerability_assessment → cve_lookup → vulnerability_scorer");
    }

    fn seed_knowledge(&mut self) {
        if !self.mm.archive.is_empty() { return; }
        let seeds: &[(&str, &str, &[&str])] = &[
            ("CVE-2024-1234: SQL injection AuthService v2.1. CVSS 9.8. Patch: v2.2+.", "knowledge_base", &["cve"]),
            ("Brute-force: 5+ failures single IP <10 min → rate-limit + SOC alert.", "playbook", &["brute-force"]),
            ("OWASP Top 10 2021: A01 Access, A02 Crypto, A03 Injection.", "knowledge_base", &["owasp"]),
            ("Security headers required: HSTS, CSP, X-Frame-Options, XCTO.", "playbook", &["headers"]),
        ];
        for (content, source, tags) in seeds {
            self.mm.archive.store(content, source, tags.iter().map(|t| t.to_string()).collect());
        }
    }

    fn exec_skill_cmd(&self, args: &str) -> String {
        let mut parts = args.trim().splitn(2, ' ');
        let name  = parts.next().unwrap_or("");
        let sargs = parts.next().unwrap_or("");
        match self.skills.get(name) {
            None => format!("⚠ Unknown skill '{}'. Try /skills", name),
            Some(skill) => {
                let r = skill.run(sargs, &self.mm);
                if r.store_to_archive && r.success && !r.archive_tags.is_empty() {
                    self.mm.archive.store(
                        &format!("[{}] {}", r.skill, &r.output[..r.output.len().min(500)]),
                        &format!("skill_{}", r.skill),
                        r.archive_tags.clone(),
                    );
                }
                r.output
            }
        }
    }

    fn chat(&self, input: &str) -> String {
        let s = input.trim();
        if s.is_empty() { return String::new(); }

        if s.starts_with('/') {
            let rest = &s[1..];
            let (cmd, args) = rest.split_once(' ').unwrap_or((rest, ""));
            return match cmd.to_lowercase().as_str() {
                "quit" | "exit" | "q" => { std::process::exit(0); }
                "skills"       => self.skills.help_text(),
                "skill"        => self.exec_skill_cmd(args),
                "react"        => {
                    if args.trim().is_empty() { return "Usage: /react <goal>".to_string(); }
                    react_run(args.trim(), &self.mm, &self.skills)
                }
                "react-step"   => {
                    let goal = if args.trim().is_empty() {
                        let g = self.mm.working.reasoning().goal();
                        if g.is_empty() { "Investigate".to_string() } else { g }
                    } else { args.to_string() };
                    let rm = self.mm.working.reasoning();
                    if !rm.enabled { self.mm.enable_react(&goal); }
                    let t0  = Instant::now();
                    let raw = match call_deepseek(&react_system(&self.mm, &self.skills), &self.mm.working.build_messages(), 0.3) {
                        Ok(r) => r,
                        Err(e) => return format!("⚠ LLM error: {}", e),
                    };
                    let lat = t0.elapsed().as_millis() as u64;
                    let (thought, action, act_args, final_) = parse_react(&raw);
                    let t = thought.unwrap_or_else(|| raw[..raw.len().min(200)].to_string());
                    rm.record(TraceType::Thought, &t, "", false, lat);
                    if let Some(ans) = final_ {
                        rm.record(TraceType::Final, &ans, "", false, 0);
                        self.mm.add_assistant_message(&ans);
                        self.mm.finish_react(&ans);
                        return format!("✅ **Final Answer:**\n{}\n\n_(done — /react-finish to archive)_", ans);
                    }
                    match action {
                        None => { rm.record(TraceType::Observation, "No Action.", "", true, 0); format!("💭 **Thought:** {}\n\n⚠ No Action produced.", t) }
                        Some(act) => {
                            let a = act_args.unwrap_or_default();
                            rm.record(TraceType::Action, &format!("{} {}", act, a), &act, false, 0);
                            let (obs, is_err) = exec_skill(&act, &a, &self.mm, &self.skills);
                            rm.record(TraceType::Observation, &obs, "", is_err, 0);
                            self.mm.working.add_message("user", &format!("Observation: {}", obs));
                            self.mm.add_assistant_message(&raw);
                            format!("💭 **Thought:** {}\n\n⚡ **Action:** `{}` {}\n\n👁 **Observation:** {}\n\n_(run /react-step again)_", t, act, &a[..a.len().min(80)], &obs[..obs.len().min(300)])
                        }
                    }
                }
                "react-status" => {
                    let rm = self.mm.working.reasoning();
                    if !rm.enabled { return "ℹ ReAct not active.".to_string(); }
                    let snap = rm.snapshot();
                    let mut lines = vec![
                        "```".to_string(),
                        format!("Goal: {}  Iters: {}  Tools: {}  Errors: {}  Elapsed: {}s",
                            snap.goal, snap.total_iterations, snap.total_tool_calls, snap.total_errors, snap.elapsed_s),
                        "```".to_string(), "**Last 6 steps:**".to_string(),
                    ];
                    let traces = rm.traces();
                    for t in traces.iter().rev().take(6).rev() { lines.push(format!("  {}", t.short())); }
                    lines.join("\n")
                }
                "react-finish" => {
                    let e = self.mm.finish_react(args);
                    match e { Some(e) => format!("✓ ReAct closed. Archived → `{}`", e.id), None => "✓ ReAct closed.".to_string() }
                }
                "task"    => {
                    let parts: Vec<&str> = args.splitn(20, '|').collect();
                    let obj = parts[0].trim();
                    if obj.is_empty() { return "Usage: /task <objective> [| step1 | ...]".to_string(); }
                    let steps: Vec<String> = parts[1..].iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    self.mm.start_task(obj, steps); format!("✓ Task: **{}**", obj)
                }
                "step"    => {
                    if !self.mm.working.status().is_active() { return "⚠ No active task.".to_string(); }
                    self.mm.complete_step(if args.trim().is_empty() { None } else { Some(args.trim()) });
                    let s = self.mm.working.status();
                    format!("✓ Step {}/{} | Next: {}", s.current_step, s.total_steps, if s.pending.is_empty() { "none".to_string() } else { s.pending.join(", ") })
                }
                "finish"  => {
                    if !self.mm.working.status().is_active() { return "⚠ No active task.".to_string(); }
                    let e = self.mm.finish_task(if args.trim().is_empty() { None } else { Some(args.trim()) });
                    format!("✓ Archived → `{}`", e.id)
                }
                "status"  => {
                    let snap = self.mm.snapshot();
                    let react = if snap.react_enabled {
                        snap.reasoning.as_ref().map(|r| format!("ON — {}", r.goal)).unwrap_or_else(|| "ON".to_string())
                    } else { "OFF".to_string() };
                    format!("```\nCharacter : {}\nLLM       : {}\nSkills    : {}\nTask      : {} ({:.1}%)\nArchive   : {} entries\nTokens≈   : {}\nReAct     : {}\n```",
                        snap.character_name, DEEPSEEK_MODEL, self.skills.skills.len(),
                        if snap.task_objective.is_empty() { "(none)".to_string() } else { snap.task_objective.clone() },
                        snap.task_progress_pct, snap.archive_total, snap.estimated_tokens, react)
                }
                "archive" => {
                    if args.trim().is_empty() { return "Usage: /archive <text>".to_string(); }
                    let e = self.mm.archive.store(args.trim(), "manual", vec![]);
                    format!("✓ Stored → `{}`", e.id)
                }
                "recall"  => {
                    if args.trim().is_empty() { return "Usage: /recall <query>".to_string(); }
                    let hits = self.mm.archive.retrieve(args.trim(), 5, 0.05);
                    if hits.is_empty() { return "No memories found.".to_string(); }
                    let mut out = "**Recall:**\n".to_string();
                    for (i, h) in hits.iter().enumerate() { out.push_str(&format!("{}. [{}] {}\n", i+1, h.source, &h.content[..h.content.len().min(120)])); }
                    out
                }
                _ => format!("Unknown command: /{}", cmd),
            };
        }

        if let Some(hint) = self.skills.detect(s) {
            self.mm.add_task_content(&format!("[Skill hint: {} — try /skill {} or /react]", hint.name(), hint.name()));
        }
        self.mm.add_user_message(s);
        let system   = self.mm.context_for_query(s, 3, 0.05);
        let messages = self.mm.working.build_messages();
        match call_deepseek(&system, &messages, 0.7) {
            Ok(reply) => { self.mm.add_assistant_message(&reply); reply }
            Err(e)    => format!("⚠ LLM error: {}", e),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let archive_path = {
        let mut args = env::args().skip(1);
        let mut path = env::var("ARCHIVE_PATH").unwrap_or_else(|_| "agent_memory.jsonl".to_string());
        while let Some(a) = args.next() {
            if a == "--archive" { if let Some(p) = args.next() { path = p; } }
        }
        path
    };

    println!("{}", BANNER);
    let agent = Agent::new(&archive_path);
    println!("  Archive : {} ({} entries)", archive_path, agent.mm.archive.len());
    println!("  Skills  : {}", agent.skills.skills.len());
    println!("  Optional: ABUSEIPDB_API_KEY  VIRUSTOTAL_API_KEY\n");

    let stdin  = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    print!("You > "); out.flush().ok();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        let t = line.trim();
        if !t.is_empty() {
            let reply = agent.chat(t);
            if !reply.is_empty() { writeln!(out, "\nAgent >\n{}\n", reply).ok(); }
        }
        write!(out, "You > ").ok(); out.flush().ok();
    }
    println!("\nGoodbye.");
}
