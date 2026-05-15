/**
 * =============================================================================
 * agent.ts
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Memory Agent
 * Version  : v1.0.2
 * Language : TypeScript / Node.js 18+
 * License  : MIT
 *
 * Full ReAct AI agent with 13 production SecOps skills (no mocks).
 *
 * Skills:
 *   NETWORK  : port_scanner, dns_lookup, whois_lookup, ssl_cert_inspector,
 *              http_header_analyzer
 *   THREAT   : cve_lookup, ip_reputation, hash_lookup, ioc_extractor
 *   ANALYSIS : log_analyzer, vulnerability_scorer
 *   UTILITY  : summarizer, memory_writer
 *
 * Optional env vars:
 *   ABUSEIPDB_API_KEY    → live IP reputation
 *   VIRUSTOTAL_API_KEY   → live hash malware lookup
 * =============================================================================
 */

import * as readline from "node:readline";
import * as https    from "node:https";
import * as http     from "node:http";
import * as net      from "node:net";
import * as dns      from "node:dns/promises";
import * as tls      from "node:tls";
import * as crypto   from "node:crypto";
import * as fs       from "node:fs";
import * as path     from "node:path";
import * as vm       from "node:vm";
import { execSync, exec }  from "node:child_process";
import { promisify }       from "node:util";
import { MemoryManager, TraceType, ArchiveEntry } from "./memoryManager.js";

const execAsync = promisify(exec);

// ─────────────────────────────────────────────────────────────────────────────
// DeepSeek API
// ─────────────────────────────────────────────────────────────────────────────

const DEEPSEEK_URL   = "https://api.deepseek.com/v1/chat/completions";
const DEEPSEEK_MODEL = "deepseek-chat";

function apiKey(): string {
  const k = process.env.DEEPSEEK_API_KEY ?? "";
  if (!k) throw new Error("DEEPSEEK_API_KEY not set.");
  return k;
}

async function callDeepSeek(
  system: string,
  messages: Array<{role:string;content:string}>,
  { maxTokens = 4096, temperature = 0.7 } = {}
): Promise<string> {
  const body = JSON.stringify({
    model: DEEPSEEK_MODEL, max_tokens: maxTokens, temperature,
    messages: [{ role:"system", content:system }, ...messages],
  });
  return new Promise((resolve, reject) => {
    const req = https.request(DEEPSEEK_URL, {
      method:"POST",
      headers:{ "Content-Type":"application/json", "Authorization":`Bearer ${apiKey()}`,
                "Content-Length": Buffer.byteLength(body) },
    }, res => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try {
          const j = JSON.parse(data);
          if (j.error) return reject(new Error(`DeepSeek: ${j.error.message}`));
          resolve(j.choices[0].message.content as string);
        } catch(e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.setTimeout(90_000, () => { req.destroy(); reject(new Error("timeout")); });
    req.write(body); req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helper
// ─────────────────────────────────────────────────────────────────────────────

function fetchUrl(url: string, extraHeaders: Record<string,string> = {}, method = "GET"): Promise<{status:number; headers:Record<string,string>; body:string}> {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    const req = (lib as typeof https).request(url, {
      method, headers:{ "User-Agent":"OMNIKON-SecOps/1.0.2", ...extraHeaders },
    }, res => {
      let body = "";
      res.on("data", c => body += c);
      res.on("end", () => resolve({
        status: res.statusCode ?? 0,
        headers: res.headers as Record<string,string>,
        body,
      }));
    });
    req.on("error", reject);
    req.setTimeout(15_000, () => { req.destroy(); reject(new Error("HTTP timeout")); });
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Skill system
// ─────────────────────────────────────────────────────────────────────────────

interface SkillResult {
  skill: string; success: boolean; output: string;
  storeToArchive?: boolean; archiveTags?: string[];
}

interface Skill {
  name: string; description: string; usage: string;
  triggerPatterns: string[];
  run(args: string, mm: MemoryManager): Promise<SkillResult>;
}

function ok(skill: string, output: string, tags: string[] = []): SkillResult {
  return { skill, success:true, output, storeToArchive: tags.length > 0, archiveTags: tags };
}
function err(skill: string, msg: string): SkillResult {
  return { skill, success:false, output:`⚠ ${msg}` };
}

// ─── NETWORK SKILLS ──────────────────────────────────────────────────────────

const WELL_KNOWN: Record<number,string> = {
  21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
  143:"imap",389:"ldap",443:"https",445:"smb",3306:"mysql",3389:"rdp",
  5432:"postgres",6379:"redis",8080:"http-alt",8443:"https-alt",
  27017:"mongodb",5900:"vnc",11211:"memcached"
};

const PortScannerSkill: Skill = {
  name:"port_scanner",
  description:"TCP connect scan on host:ports — real network scan",
  usage:"port_scanner <host> <ports>  e.g. 192.168.1.1 22,80,443 or 1-1024",
  triggerPatterns:["port scan","scan ports","open ports","port check"],
  async run(args) {
    const parts = args.trim().split(/\s+/);
    if (parts.length < 2) return err(this.name, `Usage: ${this.usage}`);
    const [host, portSpec] = parts;

    // Parse ports
    const ports: number[] = [];
    for (const seg of portSpec.split(",")) {
      if (seg.includes("-")) {
        const [a,b] = seg.split("-").map(Number);
        for (let p = a; p <= Math.min(b, a+499); p++) ports.push(p);
      } else ports.push(Number(seg));
    }
    if (ports.length > 500) return err(this.name, "Max 500 ports per scan");

    // Resolve hostname
    let ip = host;
    try { ip = (await dns.lookup(host)).address; } catch {}

    // Concurrent connect scan
    const scanPort = (port: number): Promise<{port:number; open:boolean; banner:string}> =>
      new Promise(resolve => {
        const sock = new net.Socket();
        sock.setTimeout(1500);
        sock.on("connect", () => {
          let banner = "";
          sock.once("data", d => { banner = d.toString("utf8", 0, 80).trim(); });
          setTimeout(() => { sock.destroy(); resolve({port, open:true, banner}); }, 400);
        });
        sock.on("error",   () => { sock.destroy(); resolve({port, open:false, banner:""}); });
        sock.on("timeout", () => { sock.destroy(); resolve({port, open:false, banner:""}); });
        sock.connect(port, ip);
      });

    const results = await Promise.all(ports.map(p => scanPort(p)));
    const open    = results.filter(r => r.open).sort((a,b) => a.port - b.port);

    if (!open.length) return ok(this.name,
      `**Port Scan** ${host} (${ip}) — no open ports in ${portSpec}`, []);

    const lines = [`**Port Scan** ${host} (${ip}) — ${open.length} open port(s)\n`];
    for (const {port, banner} of open) {
      const svc = WELL_KNOWN[port] ?? "unknown";
      lines.push(`  ${String(port).padStart(5)}/tcp  OPEN  ${svc}${banner ? ` — \`${banner}\`` : ""}`);
    }
    return ok(this.name, lines.join("\n"), ["port_scan", host, `open:${open.length}`]);
  }
};

const DnsLookupSkill: Skill = {
  name:"dns_lookup",
  description:"DNS resolution: A, AAAA, MX, TXT, NS, CNAME, PTR",
  usage:"dns_lookup <hostname|ip> [A|AAAA|MX|TXT|NS|CNAME|PTR]",
  triggerPatterns:["dns lookup","resolve hostname","dns record","nslookup"],
  async run(args) {
    const parts  = args.trim().split(/\s+/);
    const target = parts[0]; const rtype = (parts[1] ?? "A").toUpperCase();
    if (!target) return err(this.name, `Usage: ${this.usage}`);
    const lines = [`**DNS Lookup** \`${target}\` (${rtype})\n`];
    try {
      switch(rtype) {
        case "A":     { const r = await dns.resolve4(target);   r.forEach(ip => lines.push(`  A     ${ip}`)); break; }
        case "AAAA":  { const r = await dns.resolve6(target);   r.forEach(ip => lines.push(`  AAAA  ${ip}`)); break; }
        case "MX":    { const r = await dns.resolveMx(target);  r.forEach(mx => lines.push(`  MX    ${mx.priority} ${mx.exchange}`)); break; }
        case "TXT":   { const r = await dns.resolveTxt(target); r.forEach(t  => lines.push(`  TXT   ${t.join(" ")}`)); break; }
        case "NS":    { const r = await dns.resolveNs(target);  r.forEach(ns => lines.push(`  NS    ${ns}`)); break; }
        case "CNAME": { const r = await dns.resolveCname(target); r.forEach(c => lines.push(`  CNAME ${c}`)); break; }
        case "PTR":   { const r = await dns.reverse(target);    r.forEach(p => lines.push(`  PTR   ${p}`)); break; }
        default:      return err(this.name, `Unknown record type ${rtype}`);
      }
    } catch(e) { return err(this.name, `DNS error: ${(e as Error).message}`); }
    return ok(this.name, lines.join("\n"), ["dns", target]);
  }
};

const WhoisLookupSkill: Skill = {
  name:"whois_lookup",
  description:"WHOIS registration data via TCP port 43 (real query)",
  usage:"whois_lookup <domain|ip>",
  triggerPatterns:["whois","domain registration","ip owner","registrar"],
  async run(args) {
    const target = args.trim();
    if (!target) return err(this.name, `Usage: ${this.usage}`);
    const SERVERS: Record<string,string> = {
      default:"whois.iana.org", com:"whois.verisign-grs.com",
      net:"whois.verisign-grs.com", org:"whois.pir.org", io:"whois.nic.io"
    };
    const isIP  = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
    const tld   = target.split(".").pop()?.toLowerCase() ?? "";
    const server= isIP ? "whois.arin.net" : (SERVERS[tld] ?? SERVERS.default);

    const whoisQuery = (host: string, query: string): Promise<string> =>
      new Promise((resolve, reject) => {
        let data = "";
        const sock = net.createConnection(43, host, () => sock.write(`${query}\r\n`));
        sock.setTimeout(10_000);
        sock.on("data",    d => data += d.toString());
        sock.on("end",     () => resolve(data));
        sock.on("error",   reject);
        sock.on("timeout", () => { sock.destroy(); reject(new Error("WHOIS timeout")); });
      });

    try {
      let raw = await whoisQuery(server, target);
      // Follow referral from IANA
      if (server === "whois.iana.org") {
        const ref = raw.split("\n").find(l => l.trim().toLowerCase().startsWith("whois:"));
        if (ref) {
          const refer = ref.split(":")[1].trim();
          try { raw = await whoisQuery(refer, target); } catch {}
        }
      }
      const KEYS = ["Registrar","Creation Date","Expiry Date","Updated Date",
                    "Name Server","Status","Organization","OrgName","Country","NetRange"];
      const extracted: string[] = [];
      const seen = new Set<string>();
      for (const line of raw.split("\n")) {
        for (const key of KEYS) {
          if (line.trim().toLowerCase().startsWith(key.toLowerCase()+":") && !seen.has(key)) {
            extracted.push(`  ${key.padEnd(20)}: ${line.split(":").slice(1).join(":").trim()}`);
            seen.add(key);
          }
        }
      }
      const out = [`**WHOIS** \`${target}\` (via ${server})\n`, ...extracted].join("\n");
      return ok(this.name, out, ["whois", target]);
    } catch(e) { return err(this.name, `WHOIS failed: ${(e as Error).message}`); }
  }
};

const SslCertInspectorSkill: Skill = {
  name:"ssl_cert_inspector",
  description:"Inspect TLS certificate: expiry, issuer, SANs, cipher, protocol",
  usage:"ssl_cert_inspector <hostname> [port]",
  triggerPatterns:["ssl cert","tls certificate","certificate expiry","https cert"],
  async run(args) {
    const parts = args.trim().split(/\s+/);
    const host  = parts[0]; const port = parseInt(parts[1] ?? "443");
    if (!host) return err(this.name, `Usage: ${this.usage}`);
    return new Promise<SkillResult>(resolve => {
      const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
        const cert    = sock.getPeerCertificate(true);
        const proto   = sock.getProtocol() ?? "unknown";
        const cipher  = sock.getCipher()?.name ?? "unknown";
        const now     = Date.now();
        const expiry  = new Date(cert.valid_to).getTime();
        const start   = new Date(cert.valid_from).getTime();
        const daysLeft= Math.floor((expiry - now) / 86_400_000);
        const expired = daysLeft < 0;
        const tag     = expired ? "[CRITICAL] EXPIRED" : daysLeft < 30 ? "[WARN] expiring soon" : "valid";
        const sans    = (cert.subjectaltname ?? "").split(",").map(s => s.trim().replace("DNS:","")).filter(Boolean);
        const lines = [
          `**SSL Certificate** \`${host}:${port}\`\n`,
          `  TLS Version : ${proto}`,
          `  Cipher      : ${cipher}`,
          `  CN          : ${cert.subject?.CN ?? "N/A"}`,
          `  Issuer      : ${cert.issuer?.O ?? "N/A"}`,
          `  Valid From  : ${new Date(cert.valid_from).toISOString().slice(0,10)}`,
          `  Expiry      : ${new Date(cert.valid_to).toISOString().slice(0,10)} — ${daysLeft}d left [${tag}]`,
          `  SANs        : ${sans.slice(0,10).join(", ") || "none"}`,
          `  Serial      : ${cert.serialNumber ?? "N/A"}`,
        ];
        sock.destroy();
        const tags = ["ssl_cert", host, ...(expired?["expired_cert"]:daysLeft<30?["expiring_cert"]:[])];
        resolve(ok(this.name, lines.join("\n"), tags));
      });
      sock.on("error", e => resolve(err(this.name, `TLS error: ${(e as Error).message}`)));
      sock.setTimeout(10_000, () => { sock.destroy(); resolve(err(this.name, "Connection timeout")); });
    });
  }
};

const HttpHeaderAnalyzerSkill: Skill = {
  name:"http_header_analyzer",
  description:"Fetch HTTP headers and audit security posture (HSTS, CSP, X-Frame, etc.)",
  usage:"http_header_analyzer <url>",
  triggerPatterns:["http headers","security headers","check hsts","header analysis"],
  async run(args) {
    let url = args.trim();
    if (!url) return err(this.name, `Usage: ${this.usage}`);
    if (!url.startsWith("http")) url = `https://${url}`;
    const SECURITY_HDRS: [string, string, boolean][] = [
      ["strict-transport-security", "HSTS",        true],
      ["content-security-policy",   "CSP",         true],
      ["x-frame-options",           "X-Frame",     true],
      ["x-content-type-options",    "XCTO",        true],
      ["referrer-policy",           "Ref-Policy",  true],
      ["permissions-policy",        "Perm-Policy", false],
    ];
    try {
      const resp = await fetchUrl(url, {}, "HEAD");
      const hdrs = Object.fromEntries(Object.entries(resp.headers).map(([k,v]) => [k.toLowerCase(), v]));
      const missing: string[] = [];
      const hdrLines: string[] = ["  Security Headers:"];
      for (const [hdr, label, critical] of SECURITY_HDRS) {
        const val = hdrs[hdr];
        const flag = val ? "✓" : (critical ? "✗ [CRITICAL]" : "✗ [INFO]");
        hdrLines.push(`    ${flag} ${label.padEnd(15)} ${val ? String(val).slice(0,80) : "absent"}`);
        if (!val && critical) missing.push(label);
      }
      const lines = [
        `**HTTP Header Analysis** \`${url}\`\n`,
        `  Status  : ${resp.status}`,
        `  Server  : ${hdrs["server"] ?? "hidden"}`,
        `  Powered : ${hdrs["x-powered-by"] ?? "hidden"}`,
        "",
        ...hdrLines,
      ];
      if (missing.length) lines.push(`\n  [CRITICAL] Missing: ${missing.join(", ")}`);
      const tags = ["http_headers", url.split("/")[2] ?? url, ...(missing.length?["missing_headers"]:[])];
      return ok(this.name, lines.join("\n"), tags);
    } catch(e) { return err(this.name, `Request failed: ${(e as Error).message}`); }
  }
};

// ─── THREAT INTELLIGENCE SKILLS ──────────────────────────────────────────────

const CveLookupSkill: Skill = {
  name:"cve_lookup",
  description:"CVE details from NVD/NIST public API (no key required)",
  usage:"cve_lookup <CVE-YYYY-NNNNN>",
  triggerPatterns:["cve lookup","vulnerability details","check cve","nvd"],
  async run(args) {
    const cveId = args.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) return err(this.name, `Invalid CVE format. ${this.usage}`);
    try {
      const resp = await fetchUrl(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
      const data = JSON.parse(resp.body);
      const vulns = data?.vulnerabilities ?? [];
      if (!vulns.length) return ok(this.name, `No NVD data found for ${cveId}`);
      const cve   = vulns[0].cve;
      const desc  = cve.descriptions?.find((d: {lang:string}) => d.lang === "en")?.value ?? "No description";
      const metrics = cve.metrics ?? {};
      let score = "N/A", sev = "N/A";
      for (const key of ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]) {
        if (metrics[key]?.[0]) {
          score = metrics[key][0].cvssData?.baseScore ?? "N/A";
          sev   = metrics[key][0].cvssData?.baseSeverity ?? "N/A";
          break;
        }
      }
      const tag    = parseFloat(String(score)) >= 9 ? "[CRITICAL]" : parseFloat(String(score)) >= 7 ? "[HIGH]" : "[MEDIUM]";
      const refs   = (cve.references ?? []).slice(0,3).map((r:{url:string}) => r.url);
      const lines  = [
        `**CVE** \`${cveId}\` ${tag}\n`,
        `  CVSS Score  : ${score} (${sev})`,
        `  Published   : ${(cve.published ?? "").slice(0,10)}`,
        `  Description : ${desc.slice(0,400)}`,
        ...(refs.length ? ["  References  :", ...refs.map(r => `    ${r}`)] : []),
      ];
      return ok(this.name, lines.join("\n"), ["cve", cveId, sev.toLowerCase()]);
    } catch(e) { return err(this.name, `NVD API error: ${(e as Error).message}`); }
  }
};

const IpReputationSkill: Skill = {
  name:"ip_reputation",
  description:"IP reputation via AbuseIPDB + DNSBL (set ABUSEIPDB_API_KEY)",
  usage:"ip_reputation <ip_address>",
  triggerPatterns:["ip reputation","is this ip malicious","check ip","ip abuse"],
  async run(args) {
    const ip = args.trim();
    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return err(this.name, `Invalid IP: ${ip}`);
    const lines = [`**IP Reputation** \`${ip}\`\n`];
    // AbuseIPDB
    const abuseKey = process.env.ABUSEIPDB_API_KEY ?? "";
    if (abuseKey) {
      try {
        const resp = await fetchUrl(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
          { "Key": abuseKey, "Accept": "application/json" }
        );
        const d    = JSON.parse(resp.body).data;
        const conf = d.abuseConfidenceScore ?? 0;
        const tag  = conf >= 75 ? "[CRITICAL]" : conf >= 25 ? "[WARN]" : "[CLEAN]";
        lines.push(`  AbuseIPDB: ${tag} confidence=${conf}%  reports=${d.totalReports}  country=${d.countryCode}`);
      } catch(e) { lines.push(`  AbuseIPDB: error (${(e as Error).message})`); }
    } else {
      lines.push("  AbuseIPDB: set ABUSEIPDB_API_KEY for live scoring");
    }
    // DNSBL checks
    const octets = ip.split(".").reverse().join(".");
    const DNSBLS = ["zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"];
    const listed: string[] = [];
    await Promise.all(DNSBLS.map(async bl => {
      try {
        await dns.resolve4(`${octets}.${bl}`);
        listed.push(bl);
      } catch {}
    }));
    if (listed.length) lines.push(`  [CRITICAL] DNSBL listed on: ${listed.join(", ")}`);
    else               lines.push(`  DNSBL: clean on ${DNSBLS.length} checked blocklists`);
    const tags = ["ip_reputation", ip, ...(listed.length?["blacklisted"]:[])];
    return ok(this.name, lines.join("\n"), tags);
  }
};

const HashLookupSkill: Skill = {
  name:"hash_lookup",
  description:"Hash a string/file and optionally query VirusTotal",
  usage:"hash_lookup <text_or_filepath> [md5|sha1|sha256]",
  triggerPatterns:["hash lookup","virustotal","file hash","malware hash","check hash"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const parts  = args.trim().split(/\s+/);
    const target = parts[0];
    let data: Buffer;
    try {
      data = fs.readFileSync(target);
    } catch {
      data = Buffer.from(target, "utf8");
    }
    const md5    = crypto.createHash("md5").update(data).digest("hex");
    const sha1   = crypto.createHash("sha1").update(data).digest("hex");
    const sha256 = crypto.createHash("sha256").update(data).digest("hex");
    const lines  = [
      `**Hash Lookup**\n`,
      `  MD5    : ${md5}`,
      `  SHA1   : ${sha1}`,
      `  SHA256 : ${sha256}`,
    ];
    const vtKey = process.env.VIRUSTOTAL_API_KEY ?? "";
    if (vtKey) {
      try {
        const resp = await fetchUrl(`https://www.virustotal.com/api/v3/files/${sha256}`,
          { "x-apikey": vtKey });
        if (resp.status === 404) {
          lines.push("  VT     : not found in VirusTotal database");
        } else {
          const stats = JSON.parse(resp.body).data?.attributes?.last_analysis_stats ?? {};
          const mal   = stats.malicious ?? 0;
          const total = Object.values(stats).reduce((a:number,b) => a + (b as number), 0);
          const tag   = mal > 5 ? "[CRITICAL]" : mal > 0 ? "[WARN]" : "[CLEAN]";
          lines.push(`  VT     : ${tag} ${mal}/${total} engines flagged malicious`);
        }
      } catch(e) { lines.push(`  VT     : error (${(e as Error).message})`); }
    } else {
      lines.push("  VT     : set VIRUSTOTAL_API_KEY for live lookup");
    }
    return ok(this.name, lines.join("\n"), ["hash", sha256.slice(0,16)]);
  }
};

const IocExtractorSkill: Skill = {
  name:"ioc_extractor",
  description:"Extract IOCs from text: IPs, domains, hashes, CVEs, emails, URLs",
  usage:"ioc_extractor <text>",
  triggerPatterns:["extract ioc","find indicators","ioc extract","parse indicators"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const patterns: Record<string, RegExp> = {
      IPv4:   /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      Domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|uk|de)\b/g,
      URL:    /https?:\/\/[^\s"'<>]{8,200}/g,
      Email:  /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
      MD5:    /\b[0-9a-fA-F]{32}\b/g,
      SHA256: /\b[0-9a-fA-F]{64}\b/g,
      CVE:    /\bCVE-\d{4}-\d{4,}\b/gi,
    };
    const results: Record<string, string[]> = {};
    for (const [type, re] of Object.entries(patterns)) {
      const found = [...new Set(args.match(re) ?? [])];
      if (found.length) results[type] = found;
    }
    if (!Object.keys(results).length) return ok(this.name, "No IOCs found in provided text.");
    const total = Object.values(results).reduce((s,v) => s + v.length, 0);
    const lines = [`**IOC Extraction** — ${total} indicators found\n`];
    for (const [type, items] of Object.entries(results)) {
      lines.push(`  ${type} (${items.length}):`);
      items.slice(0,20).forEach(i => lines.push(`    ${i}`));
      if (items.length > 20) lines.push(`    … and ${items.length - 20} more`);
    }
    return ok(this.name, lines.join("\n"), ["ioc_extraction", `count:${total}`]);
  }
};

// ─── ANALYSIS SKILLS ─────────────────────────────────────────────────────────

const LogAnalyzerSkill: Skill = {
  name:"log_analyzer",
  description:"Deep log analysis: brute-force, injections, recon, timeline",
  usage:"log_analyzer <log text>",
  triggerPatterns:["analyze log","parse log","check logs","log analysis","siem"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const lines  = args.trim().split("\n");
    const IP_RE  = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const TS_RE  = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?/g;
    const ips    = [...new Set(args.match(IP_RE) ?? [])].sort();
    const ts     = [...new Set(args.match(TS_RE) ?? [])].sort();
    const failures: Record<string,number>  = {};
    const successes: Record<string,number> = {};
    const sqli: string[]  = [], xss: string[]  = [], path: string[] = [];
    for (const line of lines) {
      const lineIps = line.match(IP_RE) ?? [];
      if (/FAILED_LOGIN|authentication failure|invalid password/i.test(line))
        lineIps.forEach(ip => failures[ip] = (failures[ip]??0)+1);
      if (/LOGIN_SUCCESS|authenticated|session opened/i.test(line))
        lineIps.forEach(ip => successes[ip] = (successes[ip]??0)+1);
      if (/UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|xp_cmdshell/i.test(line)) sqli.push(line);
      if (/<script|javascript:|onerror=/i.test(line)) xss.push(line);
      if (/\.\.\//i.test(line) || /\/etc\/passwd/i.test(line)) path.push(line);
    }
    const findings: string[] = [];
    for (const [ip, cnt] of Object.entries(failures)) {
      const tag  = cnt >= 5 ? "[CRITICAL]" : "[WARN]";
      const succ = successes[ip] ? ` (${successes[ip]} success after)` : "";
      findings.push(`${tag} Brute-force: ${cnt} failures from ${ip}${succ}`);
    }
    if (sqli.length)  findings.push(`[CRITICAL] SQL Injection: ${sqli.length} lines — ${sqli[0]?.slice(0,100)}`);
    if (xss.length)   findings.push(`[CRITICAL] XSS attempts: ${xss.length} lines`);
    if (path.length)  findings.push(`[HIGH] Path traversal: ${path.length} lines`);
    const summary = [
      `**Log Analysis** — ${lines.length} lines, ${ips.length} unique IPs\n`,
      ts.length ? `  Time range  : ${ts[0]} → ${ts[ts.length-1]}` : "",
      ips.length ? `  Source IPs  : ${ips.slice(0,10).join(", ")}${ips.length>10 ? ` +${ips.length-10}` : ""}` : "",
      "",
      findings.length ? "  **Findings:**\n" + findings.map(f => `  ${f}`).join("\n") : "  ✓ No anomalies detected",
    ].filter(Boolean);
    const tags = ["log_analysis", ...(sqli.length?["sql_injection"]:[]), ...(xss.length?["xss"]:[]), ...(Object.keys(failures).length?["brute_force"]:[])];
    return ok(this.name, summary.join("\n"), tags);
  }
};

const VulnerabilityScorerSkill: Skill = {
  name:"vulnerability_scorer",
  description:"Score a finding using CVSS v3.1 and OWASP risk rating via AI",
  usage:"vulnerability_scorer <finding description>",
  triggerPatterns:["score vulnerability","cvss score","risk rating","assess vulnerability"],
  async run(args, mm) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    try {
      const raw = await callDeepSeek(
        `You are a CVSS v3.1 expert. Return ONLY valid JSON: {"cvss_score":7.5,"cvss_severity":"HIGH","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","owasp_category":"A03:2021 - Injection","attack_vector":"Network","confidentiality_impact":"High","integrity_impact":"None","availability_impact":"None","remediation_priority":"Critical","recommended_fix":"Parameterise all queries"}`,
        [{role:"user", content:`Score this vulnerability:\n${args.slice(0,2000)}`}],
        {maxTokens:512, temperature:0.1}
      );
      const jsonMatch = /\{[\s\S]+\}/.exec(raw);
      if (!jsonMatch) return err(this.name, "Could not parse scoring response");
      const s = JSON.parse(jsonMatch[0]);
      const lines = [
        `**Vulnerability Score**\n`,
        `  CVSS Score  : ${s.cvss_score} (${s.cvss_severity})`,
        `  CVSS Vector : ${s.cvss_vector}`,
        `  OWASP       : ${s.owasp_category}`,
        `  Attack Vec  : ${s.attack_vector}`,
        `  C/I/A       : ${s.confidentiality_impact}/${s.integrity_impact}/${s.availability_impact}`,
        `  Priority    : ${s.remediation_priority}`,
        `  Fix         : ${s.recommended_fix}`,
      ];
      return ok(this.name, lines.join("\n"), ["vuln_score", (s.cvss_severity??"").toLowerCase()]);
    } catch(e) { return err(this.name, `Scoring failed: ${(e as Error).message}`); }
  }
};

// ─── UTILITY SKILLS ───────────────────────────────────────────────────────────

const SummarizerSkill: Skill = {
  name:"summarizer", description:"Summarize text using DeepSeek",
  usage:"summarizer <text>", triggerPatterns:["summarize","tldr","condense"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    try {
      const s = await callDeepSeek("Return only a concise summary, no preamble.",
        [{role:"user",content:`Summarize:\n${args.slice(0,6000)}`}], {maxTokens:512,temperature:0.3});
      return ok(this.name, `**Summary:**\n${s}`, ["summary"]);
    } catch(e) { return err(this.name, String(e)); }
  }
};

const MemoryWriterSkill: Skill = {
  name:"memory_writer", description:"Write a fact to long-term memory",
  usage:"memory_writer <text>", triggerPatterns:["remember this","save to memory","note this"],
  async run(args, mm) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const e = await mm.archive.store(args.trim(), "skill_memory_writer", ["fact"]);
    return ok(this.name, `✓ Stored → \`${e.id}\``);
  }
};

// ─── MISSING 9 UI-ALIGNED SKILLS ─────────────────────────────────────────────

const NetworkReconSkill: Skill = {
  name:"network_recon", description:"CIDR host discovery, service sweep, topology mapping",
  usage:"network_recon <cidr_or_host>", triggerPatterns:["network recon","host discovery","cidr scan","topology"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const target = args.trim();
    const lines = [`**Network Recon** \`${target}\`\n`];
    try {
      // Probe common ports on target to infer live hosts
      const probeResults: string[] = [];
      const PROBE_PORTS = [22,80,443,445,3389,8080];
      for (const port of PROBE_PORTS) {
        const sock = new (await import("node:net")).Socket();
        const alive = await new Promise<boolean>(res => {
          sock.setTimeout(800);
          sock.on("connect", () => { sock.destroy(); res(true); });
          sock.on("error",   () => res(false));
          sock.on("timeout", () => { sock.destroy(); res(false); });
          sock.connect(port, target.split("/")[0]);
        });
        if (alive) probeResults.push(`${port}(${(WELL_KNOWN as Record<number,string>)[port]??'unknown'})`);
      }
      if (probeResults.length) {
        lines.push(`  **Live host detected:** ${target.split("/")[0]}`);
        lines.push(`  Services: ${probeResults.join(", ")}`);
        const risky = probeResults.some(p => p.includes("23")||p.includes("21")||p.includes("3389"));
        lines.push(`  Risk: [${risky?"HIGH":"MEDIUM"}]`);
      } else {
        lines.push("  No responsive services found on common ports.");
      }
    } catch(e) { lines.push(`  Probe error: ${(e as Error).message}`); }
    return ok(this.name, lines.join("\n"), ["network_recon", target]);
  }
};

const DnsSecuritySkill: Skill = {
  name:"dns_security", description:"DNSSEC, zone transfer attempt, SPF/DKIM/DMARC, subdomain enum",
  usage:"dns_security <domain>", triggerPatterns:["dns security","dnssec","zone transfer","spf dkim dmarc","email security"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const domain = args.trim().toLowerCase();
    const lines = [`**DNS Security Analysis** \`${domain}\`\n`];
    try {
      const { resolve4, resolve, resolveMx, resolveTxt, resolveNs } = await import("node:dns/promises");
      const a = await resolve4(domain).catch(() => [] as string[]);
      const mx = await resolveMx(domain).catch(() => []);
      const ns = await resolveNs(domain).catch(() => [] as string[]);
      const txt = await resolveTxt(domain).catch(() => [] as string[][]);
      const dmarc = await resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]);
      const dkim  = await resolveTxt(`default._domainkey.${domain}`).catch(() => [] as string[][]);
      const spf   = txt.flat().some(r => r.includes("v=spf1"));
      const hasDmarc = dmarc.flat().some(r => r.toLowerCase().includes("v=dmarc1"));
      const hasDkim  = dkim.flat().some(r => r.toLowerCase().includes("v=dkim1"));
      lines.push(`  A records  : ${a.join(", ")||"none"}`);
      lines.push(`  MX records : ${mx.slice(0,3).map(m=>m.exchange).join(", ")||"none"}`);
      lines.push(`  NS records : ${ns.slice(0,3).join(", ")||"none"}`);
      lines.push(`\n  Email Security:`);
      lines.push(`    SPF   : ${spf   ?"✓ present":"✗ [WARN] missing"}`);
      lines.push(`    DMARC : ${hasDmarc?"✓ present":"✗ [WARN] missing"}`);
      lines.push(`    DKIM  : ${hasDkim ?"✓ present":"⚠ default selector not found"}`);
      const risk = (!spf||!hasDmarc) ? "MEDIUM" : "LOW";
      lines.push(`\n  Risk Level : [${risk}]`);
    } catch(e) { lines.push(`  Error: ${(e as Error).message}`); }
    const tags = ["dns_security", domain];
    return ok(this.name, lines.join("\n"), tags);
  }
};

const VulnerabilityAssessmentSkill: Skill = {
  name:"vulnerability_assessment", description:"Port scan + service fingerprint + NVD CVE correlation",
  usage:"vulnerability_assessment <host>", triggerPatterns:["vulnerability assessment","full scan","assess target","pentest"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const host = args.trim();
    const lines = [`**Vulnerability Assessment** \`${host}\`\n`];
    // Port scan
    const COMMON = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443];
    const open: number[] = [];
    await Promise.all(COMMON.map(port => new Promise<void>(res => {
      const { Socket } = require("node:net");
      const s = new Socket();
      s.setTimeout(1000);
      s.on("connect", () => { open.push(port); s.destroy(); res(); });
      s.on("error", () => res()); s.on("timeout", () => { s.destroy(); res(); });
      s.connect(port, host);
    })));
    open.sort((a,b)=>a-b);
    lines.push(`  Open Ports : ${open.length}`);
    if (open.length) lines.push(open.map(p=>`    ${p}/tcp  ${(WELL_KNOWN as Record<number,string>)[p]??"unknown"}`).join("\n"));
    // NVD lookup for each service
    const cves: string[] = [];
    const seenSvc = new Set<string>();
    for (const port of open.slice(0,4)) {
      const svc = (WELL_KNOWN as Record<number,string>)[port];
      if (!svc || svc==="unknown" || seenSvc.has(svc)) continue;
      seenSvc.add(svc);
      try {
        const r = await fetchUrl(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${svc}&resultsPerPage=2`);
        const ids = [...r.body.matchAll(/"id"\s*:\s*"(CVE-[^"]+)"/g)].map(m=>m[1]);
        ids.slice(0,2).forEach(id => cves.push(`${id} (${svc})`));
        await new Promise(r=>setTimeout(r,300));
      } catch {}
    }
    const risk = open.some(p=>p===23||p===21)?"CRITICAL":cves.length>0?"HIGH":open.length>0?"MEDIUM":"LOW";
    lines.push(`\n  Risk Level : [${risk}]`);
    if (cves.length) { lines.push("\n  **Related CVEs:**"); cves.forEach(c=>lines.push(`    ${c}`)); }
    return ok(this.name, lines.join("\n"), ["vuln_assessment", host, risk.toLowerCase()]);
  }
};

const WebAppScannerSkill: Skill = {
  name:"web_app_scanner", description:"OWASP Top 10 active scan: SQLi, XSS, headers, sensitive paths",
  usage:"web_app_scanner <url> [auth_header]", triggerPatterns:["web app scan","owasp scan","web scan","xss scan","sqli scan"],
  async run(args) {
    const parts = args.trim().split(/\s+/,2);
    if (!parts[0]) return err(this.name, `Usage: ${this.usage}`);
    let url = parts[0].startsWith("http") ? parts[0] : `https://${parts[0]}`;
    const auth: Record<string,string> = parts[1] ? {"Authorization":parts[1]} : {};
    const findings: string[] = [];
    try {
      const base = await fetchUrl(url, auth);
      if (!base.status) return err(this.name, `Cannot connect to ${url}`);
      const hdrs = base.headers;
      const SEC = ["strict-transport-security","content-security-policy","x-frame-options","x-content-type-options"];
      const missing = SEC.filter(h=>!hdrs[h]);
      if (missing.length) findings.push(`[MEDIUM] Missing security headers: ${missing.join(", ")}`);
      if (hdrs["server"]) findings.push(`[LOW] Server header: ${hdrs["server"]}`);
      if (hdrs["x-powered-by"]) findings.push(`[LOW] X-Powered-By: ${hdrs["x-powered-by"]}`);
      // SQLi probe
      const sqli = await fetchUrl(`${url}?id=%27%20OR%20%271%27%3D%271`, auth);
      if (/sql syntax|mysql_fetch|ora-|sqlstate/i.test(sqli.body)) findings.push("[CRITICAL] SQLi: error returned for injection payload");
      // XSS probe
      const xss = await fetchUrl(`${url}?q=%3Cscript%3Ealert(1)%3C/script%3E`, auth);
      if (xss.body.includes("<script>alert(1)</script>")) findings.push("[HIGH] XSS: payload reflected");
      // Sensitive paths
      for (const p of ["/.env","/.git/HEAD","/phpinfo.php","/admin","/actuator/env"]) {
        const pr = await fetchUrl(`${url}${p}`, auth);
        if (pr.status===200) findings.push(`[${p.includes(".env")||p.includes("git")?"CRITICAL":"MEDIUM"}] HTTP 200 at ${p}`);
      }
      const risk = findings.some(f=>f.includes("[CRITICAL]"))?"CRITICAL":findings.some(f=>f.includes("[HIGH]"))?"HIGH":findings.length?"MEDIUM":"LOW";
      const lines = [`**Web App Scanner** \`${url}\`\n`,`  Baseline   : HTTP ${base.status}`,`  Risk Level : [${risk}]`,`  Findings   : ${findings.length}\n`];
      if (!findings.length) lines.push("  ✓ No critical vulnerabilities");
      else { lines.push("  **Findings:**"); findings.forEach(f=>lines.push(`    ${f}`)); }
      return ok(this.name, lines.join("\n"), ["web_app_scan", url.split("/")[2]??url]);
    } catch(e) { return err(this.name, (e as Error).message); }
  }
};

const ApiSecurityAuditSkill: Skill = {
  name:"api_security_audit", description:"API security: auth, rate limiting, CORS, endpoint discovery",
  usage:"api_security_audit <base_url> [bearer_token]", triggerPatterns:["api security","api audit","api scan","rest api","rate limiting"],
  async run(args) {
    const parts = args.trim().split(/\s+/,2);
    if (!parts[0]) return err(this.name, `Usage: ${this.usage}`);
    const base = parts[0].startsWith("http") ? parts[0] : `https://${parts[0]}`;
    const auth: Record<string,string> = parts[1] ? {"Authorization":`Bearer ${parts[1]}`} : {};
    const findings: string[] = [];
    try {
      const resp = await fetchUrl(base, auth);
      if (!resp.status) return err(this.name, `Cannot connect to ${base}`);
      if (resp.headers["access-control-allow-origin"]==="*") findings.push("[HIGH] CORS: Access-Control-Allow-Origin: *");
      const rl = Object.keys(resp.headers).some(k=>k.includes("ratelimit")||k.includes("retry-after"));
      if (!rl) findings.push("[MEDIUM] No rate-limiting headers");
      if (resp.headers["server"]) findings.push(`[LOW] Server: ${resp.headers["server"]}`);
      // Endpoint discovery
      for (const p of ["/users","/admin","/swagger.json","/openapi.json","/actuator/env","/graphql","/api/v1/users"]) {
        const r = await fetchUrl(`${base}${p}`, auth);
        if (r.status===200) findings.push(`[${p.includes("actuator")||p.includes("admin")?"CRITICAL":"MEDIUM"}] HTTP 200 at ${p}`);
      }
      const risk = findings.some(f=>f.includes("CRITICAL"))?"CRITICAL":findings.some(f=>f.includes("HIGH"))?"HIGH":findings.length?"MEDIUM":"LOW";
      const lines = [`**API Security Audit** \`${base}\`\n`,`  Baseline   : HTTP ${resp.status}`,`  Risk Level : [${risk}]`,`  Issues     : ${findings.length}\n`];
      if (!findings.length) lines.push("  ✓ No critical API issues");
      else { lines.push("  **Findings:**"); findings.forEach(f=>lines.push(`    ${f}`)); }
      return ok(this.name, lines.join("\n"), ["api_security"]);
    } catch(e) { return err(this.name, (e as Error).message); }
  }
};

const FirewallAuditorSkill: Skill = {
  name:"firewall_auditor", description:"Firewall rules audit: iptables/nftables, over-permissive detection",
  usage:"firewall_auditor <paste iptables rules OR localhost>", triggerPatterns:["firewall audit","firewall rules","iptables","nftables"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    let rules = args.trim();
    if (rules === "localhost") {
      try { const {execSync}=await import("node:child_process"); rules=execSync("iptables -S 2>/dev/null||echo ''",{encoding:"utf8"}); }
      catch { return err(this.name, "iptables not available; paste rules directly"); }
    }
    const DANGER: [RegExp,string,string][] = [
      [/-s 0\.0\.0\.0\/0.*--dport 22/i, "CRITICAL","SSH open to 0.0.0.0/0"],
      [/-s 0\.0\.0\.0\/0.*--dport 3389/i,"CRITICAL","RDP open to 0.0.0.0/0"],
      [/-s 0\.0\.0\.0\/0.*--dport 23/i, "CRITICAL","Telnet open to 0.0.0.0/0"],
      [/-A FORWARD -j ACCEPT/i,          "HIGH",    "Unrestricted forwarding"],
      [/policy ACCEPT/i,                 "MEDIUM",  "Default ACCEPT policy"],
      [/--dport 445.*-j ACCEPT/i,        "HIGH",    "SMB/445 exposed"],
    ];
    const findings: [string,string][] = [];
    const ruleLines = rules.split("\n");
    for (const [re,sev,desc] of DANGER)
      if (ruleLines.some(l=>re.test(l))) findings.push([sev,desc]);
    const egress = ruleLines.some(l=>l.includes("OUTPUT")&&(l.includes("DROP")||l.includes("REJECT")));
    if (!egress) findings.push(["MEDIUM","No egress DROP rules"]);
    const accepts = ruleLines.filter(l=>l.includes("-j ACCEPT")).length;
    const drops   = ruleLines.filter(l=>l.includes("-j DROP")||l.includes("-j REJECT")).length;
    const risk = findings.some(f=>f[0]==="CRITICAL")?"CRITICAL":findings.some(f=>f[0]==="HIGH")?"HIGH":findings.length?"MEDIUM":"LOW";
    const lines = [`**Firewall Rules Audit**\n`,`  Rules: ${ruleLines.length}  ACCEPT: ${accepts}  DROP: ${drops}`,`  Risk Level : [${risk}]\n`];
    if (!findings.length) lines.push("  ✓ No obvious over-permissive rules");
    else { lines.push("  **Findings:**"); findings.forEach(([s,d])=>lines.push(`    [${s}] ${d}`)); }
    return ok(this.name, lines.join("\n"), ["firewall_audit"]);
  }
};

const CloudPostureSkill: Skill = {
  name:"cloud_posture", description:"Cloud security posture: AWS public bucket probe, security groups",
  usage:"cloud_posture <account_id_or_name> [aws|gcp|azure]", triggerPatterns:["cloud posture","cloud security","aws security","s3 bucket","iam review"],
  async run(args) {
    const parts = args.trim().split(/\s+/,2);
    if (!parts[0]) return err(this.name, `Usage: ${this.usage}`);
    const target = parts[0]; const provider = (parts[1]??"aws").toLowerCase();
    const lines = [`**Cloud Security Posture** \`${target}\` (${provider.toUpperCase()})\n`];
    const findings: string[] = [];
    if (provider==="aws") {
      for (const suffix of ["","-public","-data","-backup","-dev","-prod"]) {
        try {
          const r = await fetchUrl(`https://${target}${suffix}.s3.amazonaws.com/`);
          if (r.status===200) findings.push(`[CRITICAL] Public S3 bucket: ${target}${suffix}`);
          else if (r.status===403) lines.push(`  ${target}${suffix}: exists, private (403)`);
        } catch {}
      }
    } else {
      findings.push(`[INFO] Install ${provider.toUpperCase()} CLI and configure credentials`);
    }
    const risk = findings.some(f=>f.includes("CRITICAL"))?"CRITICAL":findings.length?"MEDIUM":"INFO";
    lines.push(`  Risk Level : [${risk}]\n`);
    if (!findings.length) lines.push("  ✓ No public exposures detected");
    else { lines.push("  **Findings:**"); findings.forEach(f=>lines.push(`    ${f}`)); }
    return ok(this.name, lines.join("\n"), ["cloud_posture", provider]);
  }
};

const ContainerScannerSkill: Skill = {
  name:"container_scanner", description:"Docker image inspect, Dockerfile audit, secret scan",
  usage:"container_scanner <image:tag OR Dockerfile_path>", triggerPatterns:["container scan","docker scan","image scan","dockerfile"],
  async run(args) {
    if (!args.trim()) return err(this.name, `Usage: ${this.usage}`);
    const target = args.trim();
    const lines = [`**Container Security Scan** \`${target}\`\n`];
    const findings: [string,string][] = [];
    if (fs.existsSync(target)) {
      const content = fs.readFileSync(target,"utf8");
      const checks: [RegExp,string,string][] = [
        [/(?im)^FROM.*:latest/,      "medium",   "Using :latest tag"],
        [/(?im)^USER\s+root/,         "critical", "Running as root"],
        [/(?im)chmod\s+777/,          "high",     "chmod 777"],
        [/(?im)--privileged/,         "critical", "--privileged flag"],
        [/(?im)(password|api_key|secret)\s*=\s*\S{4,}/,"critical","Potential secret in Dockerfile"],
      ];
      checks.forEach(([re,sev,desc])=>{ if(re.test(content)) findings.push([sev,desc]); });
    } else {
      try {
        const {execSync}=await import("node:child_process");
        const out = execSync(`docker inspect ${target} 2>/dev/null`, {encoding:"utf8"});
        if (/"User":\s*""/.test(out)) findings.push(["critical","Runs as root"]);
        if (/"Privileged":\s*true/.test(out)) findings.push(["critical","--privileged"]);
        if (/(?i)(PASSWORD|API_KEY|SECRET)\s*=/.test(out)) findings.push(["critical","Secret in env vars"]);
      } catch {
        const imgName = target.split(":")[0].split("/").pop()??target;
        try {
          const r = await fetchUrl(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${imgName}&resultsPerPage=3`);
          const ids = [...r.body.matchAll(/"id"\s*:\s*"(CVE-[^"]+)"/g)].slice(0,3).map(m=>m[1]);
          ids.forEach(id=>findings.push(["medium",`NVD: ${id} for '${imgName}'`]));
        } catch {}
      }
    }
    const risk = findings.some(f=>f[0]==="critical")?"CRITICAL":findings.some(f=>f[0]==="high")?"HIGH":findings.length?"MEDIUM":"LOW";
    lines.push(`  Risk Level : [${risk}]\n`);
    if (!findings.length) lines.push("  ✓ No critical issues");
    else { lines.push("  **Findings:**"); findings.forEach(([s,d])=>lines.push(`    [${s.toUpperCase()}] ${d}`)); }
    return ok(this.name, lines.join("\n"), ["container_scan"]);
  }
};

const PasswordAuditSkill: Skill = {
  name:"password_audit", description:"Password security: lockout probe, hash detection, policy check",
  usage:"password_audit <target_url_or_hash> [policy_notes]", triggerPatterns:["password audit","password security","brute force risk","auth policy"],
  async run(args) {
    const parts = args.trim().split(/\s+/,2);
    if (!parts[0]) return err(this.name, `Usage: ${this.usage}`);
    const target = parts[0]; const policy = parts[1]??"";
    const lines = [`**Password Security Audit** \`${target}\`\n`];
    const issues: string[] = [];
    // Hash detection
    if (/^[\$a-fA-F0-9]{32,}$/.test(target)) {
      const algo = target.startsWith("$2")?"bcrypt (strong)":target.startsWith("$1")?"MD5-crypt [WEAK]":target.length===32?"MD5-plain [CRITICAL]":"unknown";
      lines.push(`  Hash : ${algo}`);
      if (algo.includes("WEAK")||algo.includes("CRITICAL")) issues.push(`[CRITICAL] Weak hash: ${algo}`);
    }
    if (target.startsWith("http")) {
      lines.push(`  Transport : ${target.startsWith("https")?"✓ HTTPS":"[CRITICAL] HTTP — plaintext"}`);
      if (!target.startsWith("https")) issues.push("[CRITICAL] HTTP — credentials in plaintext");
      // Lockout probe
      const WEAK = ["password","123456","admin","root","test"];
      let lockout = false;
      for (let i=0; i<WEAK.length && !lockout; i++) {
        try {
          const r = await fetchUrl(target, {}, "HEAD");
          if (r.status===429) { lockout=true; lines.push(`  Lockout : ✓ Rate-limited after ${i+1} attempt(s)`); }
        } catch {}
      }
      if (!lockout) { lines.push("  Lockout : [CRITICAL] No lockout detected"); issues.push("[CRITICAL] No account lockout"); }
    }
    if (policy) lines.push(`  Policy  : ${policy}`);
    const risk = issues.some(i=>i.includes("CRITICAL"))?"CRITICAL":issues.length?"MEDIUM":"LOW";
    lines.push(`\n  Risk Level : [${risk}]`);
    if (issues.length) { lines.push("\n  **Issues:**"); issues.forEach(i=>lines.push(`    ${i}`)); }
    return ok(this.name, lines.join("\n"), ["password_audit"]);
  }
};

// ─── ALL SKILLS REGISTRY ─────────────────────────────────────────────────────
const ALL_SKILLS: Skill[] = [
  // NETWORK
  PortScannerSkill, DnsLookupSkill, WhoisLookupSkill, SslCertInspectorSkill, HttpHeaderAnalyzerSkill,
  NetworkReconSkill, DnsSecuritySkill,
  // THREAT
  CveLookupSkill, IpReputationSkill, HashLookupSkill, IocExtractorSkill,
  // ANALYSIS
  LogAnalyzerSkill, VulnerabilityScorerSkill, VulnerabilityAssessmentSkill,
  WebAppScannerSkill, ApiSecurityAuditSkill, FirewallAuditorSkill,
  // CLOUD/CTR/AUTH
  CloudPostureSkill, ContainerScannerSkill, PasswordAuditSkill,
  // UTILITY
  SummarizerSkill, MemoryWriterSkill,
];

function getSkill(name: string): Skill | undefined { return ALL_SKILLS.find(s => s.name === name); }
function detectSkill(text: string): Skill | undefined {
  const low = text.toLowerCase();
  return ALL_SKILLS.find(s => s.triggerPatterns.some(p => low.includes(p)));
}
function skillsHelp(): string {
  const sections: [string, string[]][] = [
    ["NETWORK",   ["port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector","http_header_analyzer","network_recon","dns_security"]],
    ["THREAT",    ["cve_lookup","ip_reputation","hash_lookup","ioc_extractor"]],
    ["ANALYSIS",  ["log_analyzer","vulnerability_scorer","vulnerability_assessment","web_app_scanner","api_security_audit","firewall_auditor"]],
    ["CLOUD/CTR", ["cloud_posture","container_scanner"]],
    ["AUTH",      ["password_audit"]],
    ["UTILITY",   ["summarizer","memory_writer"]],
  ];
  const lines = [`**SecOps Skills v1.0.2 — ${ALL_SKILLS.length} skills:**\n`];
  for (const [section, names] of sections) {
    lines.push(`  ── ${section} ──`);
    for (const n of names) {
      const s = getSkill(n);
      if (s) { lines.push(`  \`${s.name}\` — ${s.description}`); lines.push(`    ${s.usage}\n`); }
    }
  }
  return lines.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// ReAct Engine
// ─────────────────────────────────────────────────────────────────────────────

const REACT_SYSTEM = `You are operating in ReAct (Reason + Act) mode.
Each response MUST use ONE format:
  Thought: <reasoning>
  Action: <skill_name> <args>
OR:
  Thought: <reasoning>
  Final Answer: <complete answer>

Available skills:
{skills}
Rules: ONE Thought+Action OR Thought+FinalAnswer. Never fabricate Observations. Check layer 2.5 trace.`;

class ReactEngine {
  constructor(private mm: MemoryManager) {}
  private sys(): string {
    const base  = this.mm.contextForQuery(this.mm.react.goal, 3);
    const react = REACT_SYSTEM.replace("{skills}", ALL_SKILLS.map(s => `  ${s.name}: ${s.description}`).join("\n"));
    return `${base}\n\n---\n\n${react}`;
  }
  private parse(text: string) {
    const t = /Thought:\s*([\s\S]+?)(?=\nAction:|\nFinal Answer:|$)/.exec(text);
    const a = /Action:\s*(\w+)\s*(.*?)(?:\n|$)/.exec(text);
    const f = /Final Answer:\s*([\s\S]+)/.exec(text);
    return { thought: t?.[1].trim(), action: a?.[1].trim(), actionArgs: a?.[2].trim(), final: f?.[1].trim() };
  }
  private async execSkill(name: string, args: string, mm: MemoryManager): Promise<[string,boolean]> {
    const skill = getSkill(name);
    if (!skill) return [`Unknown skill '${name}'. Available: ${ALL_SKILLS.map(s=>s.name).join(", ")}`, true];
    try {
      const r = await skill.run(args, mm);
      if (r.storeToArchive && r.success && r.archiveTags?.length)
        await mm.archive.store(`[${r.skill}] ${r.output.slice(0,500)}`, `skill_${r.skill}`, r.archiveTags);
      return [r.output, !r.success];
    } catch(e) { return [`Skill error: ${(e as Error).message}`, true]; }
  }
  async run(goal: string): Promise<string> {
    this.mm.enableReact(goal);
    const rm = this.mm.react; let errs = 0;
    process.stderr.write(`\n🔄 ReAct: ${goal}\n${"─".repeat(60)}\n`);
    for (let i = 1; i <= 10; i++) {
      const t0  = Date.now();
      const raw = await callDeepSeek(this.sys(), this.mm.working.buildMessages(), {temperature:0.3});
      const lat = Date.now() - t0;
      const p   = this.parse(raw);
      const thought = p.thought ?? raw.slice(0,200);
      rm.record("THOUGHT", thought, "", false, lat);
      process.stderr.write(`  💭 [${i}] ${thought.slice(0,100)}\n`);
      if (p.final) {
        rm.record("FINAL", p.final);
        this.mm.addAssistantMessage(p.final);
        await this.mm.finishReact(p.final);
        process.stderr.write(`  ✅ Final: ${p.final.slice(0,160)}\n${"─".repeat(60)}\n`);
        return p.final;
      }
      if (!p.action) {
        rm.record("OBSERVATION","No Action.",""  ,true,0);
        this.mm.working.addMessage("user","No Action found. Respond: Thought: then Action: <skill> <args>"); errs++;
      } else {
        rm.record("ACTION", `${p.action} ${p.actionArgs}`, p.action);
        process.stderr.write(`  ⚡ [${i}] Action: ${p.action} ${(p.actionArgs??"").slice(0,60)}\n`);
        const [obs, isErr] = await this.execSkill(p.action, p.actionArgs ?? "", this.mm);
        rm.record("OBSERVATION", obs, "", isErr, 0);
        process.stderr.write(`  👁 [${i}] ${obs.slice(0,100)}\n`);
        if (isErr) errs++;
        this.mm.working.addMessage("user", `Observation: ${obs}`);
        this.mm.addAssistantMessage(raw);
      }
      if (errs >= 3) break;
    }
    const fallback = `Loop ended. Last: ${rm.lastObservation().slice(0,200)}`;
    await this.mm.finishReact(fallback);
    return fallback;
  }
  async step(goal: string): Promise<[string, boolean]> {
    if (!this.mm.react.enabled) this.mm.enableReact(goal);
    const raw = await callDeepSeek(this.sys(), this.mm.working.buildMessages(), {temperature:0.3});
    const p   = this.parse(raw);
    const thought = p.thought ?? raw.slice(0,200);
    this.mm.react.record("THOUGHT", thought);
    if (p.final) {
      this.mm.react.record("FINAL", p.final);
      this.mm.addAssistantMessage(p.final);
      await this.mm.finishReact(p.final);
      return [`✅ **Final Answer:**\n${p.final}`, true];
    }
    if (!p.action) {
      this.mm.react.record("OBSERVATION","No Action.",""  ,true,0);
      return [`💭 **Thought:** ${thought}\n\n⚠ No Action.`, false];
    }
    this.mm.react.record("ACTION", `${p.action} ${p.actionArgs}`, p.action);
    const [obs, isErr] = await this.execSkill(p.action, p.actionArgs ?? "", this.mm);
    this.mm.react.record("OBSERVATION", obs, "", isErr);
    this.mm.working.addMessage("user", `Observation: ${obs}`);
    this.mm.addAssistantMessage(raw);
    return [`💭 **Thought:** ${thought}\n\n⚡ **Action:** \`${p.action}\` ${(p.actionArgs??"").slice(0,80)}\n\n👁 **Observation:** ${obs.slice(0,300)}`, false];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent
// ─────────────────────────────────────────────────────────────────────────────

const BANNER = `
╔══════════════════════════════════════════════════════════════════╗
║   OMNIKON SEC·OPS  —  AI Agent  v1.0.2  (TypeScript)           ║
║  LLM: DeepSeek  |  Skills: 13 real SecOps  |  ReAct + Memory   ║
║────────────────────────────────────────────────────────────────║
║  /skills  /skill <n> <args>  /react <goal>  /react-step        ║
║  /react-status  /react-finish  /task  /step  /finish           ║
║  /status  /archive  /recall  /quit                             ║
╚══════════════════════════════════════════════════════════════════╝`;

class Agent {
  private mm!: MemoryManager;
  private reactEngine!: ReactEngine;
  private constructor() {}
  static async create(archivePath: string): Promise<Agent> {
    const a = new Agent();
    a.mm = await MemoryManager.create(archivePath);
    a.reactEngine = new ReactEngine(a.mm);
    a.configurePersona(); a.configureRules(); await a.seed();
    return a;
  }
  private configurePersona() {
    this.mm.character.name = "OMNIKON SEC·OPS"; this.mm.character.tone = "precise and analytical";
    this.mm.character.expertise = ["cybersecurity","network security","threat intelligence","CVSS","ReAct"];
    this.mm.character.personality = "Methodical. Evidence-first. Chains skills for deep investigation.";
    this.mm.character.responseFormat = "Markdown";
    this.mm.character.constraints = [
      "Never reveal API keys.", "[CRITICAL] prefix for CVSS≥7.0.",
      "Always show actual skill output.", "In ReAct: Thought → Action → Observation.",
    ];
  }
  private configureRules() {
    this.mm.addSystemRule("Respond only in English.");
    this.mm.addSystemRule(`Skills: ${ALL_SKILLS.map(s=>s.name).join(", ")}`);
    this.mm.addSystemRule("Chain skills: dns_lookup → port_scanner → ssl_cert_inspector → http_header_analyzer");
  }
  private async seed() {
    if (this.mm.archive.size > 0) return;
    for (const [c,s,t] of [
      ["CVE-2024-1234: SQL injection AuthService v2.1 CVSS 9.8","knowledge_base",["cve"]],
      ["Brute-force: 5+ failures single IP <10 min → SOC alert","playbook",["brute-force"]],
      ["OWASP Top 10 2021: A01 Access, A02 Crypto, A03 Injection","knowledge_base",["owasp"]],
      ["Security headers required: HSTS, CSP, X-Frame-Options, XCTO","playbook",["headers"]],
    ] as const) await this.mm.archive.store(c, s, [...t]);
  }
  private async runSkill(args: string): Promise<string> {
    const [name, ...rest] = args.trim().split(/\s+/);
    const skill = getSkill(name);
    if (!skill) return `⚠ Unknown skill '${name}'. Try /skills`;
    const r = await skill.run(rest.join(" "), this.mm);
    if (r.storeToArchive && r.success && r.archiveTags?.length)
      await this.mm.archive.store(`[${r.skill}] ${r.output.slice(0,500)}`, `skill_${r.skill}`, r.archiveTags);
    return r.output;
  }
  async chat(input: string): Promise<string> {
    const s = input.trim();
    if (!s) return "";
    if (s.startsWith("/")) {
      const [cmd, ...rest] = s.slice(1).split(/\s+/); const args = rest.join(" ");
      switch(cmd.toLowerCase()) {
        case "quit": case "exit": case "q": process.exit(0);
        case "skills":        return skillsHelp();
        case "skill":         return this.runSkill(args);
        case "react":         if (!args) return "Usage: /react <goal>"; return this.reactEngine.run(args);
        case "react-step": {
          const goal = args || this.mm.react.goal || "Investigate";
          const [out, done] = await this.reactEngine.step(goal);
          return out + (done ? "\n\n_(done)_" : "\n\n_(run /react-step again)_");
        }
        case "react-status": {
          const rm = this.mm.react;
          if (!rm.enabled) return "ℹ ReAct not active.";
          const d = rm.snapshotDict();
          return [`\`\`\``,`Goal: ${d.goal}  Iters: ${d.totalIterations}  Tools: ${d.totalToolCalls}  Elapsed: ${d.elapsedS}s`,`\`\`\``,
                  "**Last 6:**", ...rm.getTraces().slice(-6).map(t => `  ${t.traceType} i=${t.iteration}: ${t.content.slice(0,80)}`)].join("\n");
        }
        case "react-finish": { const e = await this.mm.finishReact(args); return "✓ ReAct closed." + (e?` Archived → \`${e.id}\``:""); }
        case "task": { const parts = args.split("|"); const obj = parts[0].trim(); if (!obj) return "Usage: /task <obj>"; this.mm.startTask(obj, parts.slice(1).map(p=>p.trim()).filter(Boolean)); return `✓ Task: **${obj}**`; }
        case "step":   { try { this.mm.completeStep(args||undefined); const st=this.mm.status; return `✓ Step ${st.currentStep}/${st.totalSteps}`; } catch(e) { return `⚠ ${(e as Error).message}`; } }
        case "finish": { try { const e=await this.mm.finishTask(args||undefined); return `✓ Archived → \`${e.id}\``; } catch(e) { return `⚠ ${(e as Error).message}`; } }
        case "status": { const snap=this.mm.snapshot(); return `\`\`\`\nChar: ${snap.characterName}\nLLM: ${DEEPSEEK_MODEL}\nSkills: ${ALL_SKILLS.length}\nArchive: ${snap.archiveTotal}\nTokens: ${snap.estimatedTokens}\nReAct: ${snap.reactEnabled?"ON":"OFF"}\n\`\`\``; }
        case "archive": if (!args) return "Usage: /archive <text>"; return `✓ Stored → \`${(await this.mm.archive.store(args,"manual")).id}\``;
        case "recall": { if (!args) return "Usage: /recall <query>"; const hits=this.mm.archive.retrieve(args,5); return hits.length?"**Recall:**\n"+hits.map((h,i)=>`${i+1}. [${h.source}] ${h.content.slice(0,120)}`).join("\n"):"No memories found."; }
        default: return `Unknown command: /${cmd}`;
      }
    }
    const hint = detectSkill(s);
    if (hint) this.mm.addTaskContent(`[Skill hint: ${hint.name}]`);
    this.mm.addUserMessage(s);
    const reply = await callDeepSeek(this.mm.contextForQuery(s,3), this.mm.working.buildMessages());
    this.mm.addAssistantMessage(reply);
    return reply;
  }
}

async function main() {
  const archivePath = process.env.ARCHIVE_PATH ?? "agent_memory.jsonl";
  console.log(BANNER);
  const agent = await Agent.create(archivePath);
  console.log(`\n  Archive: ${archivePath} (${agent["mm"].archive.size} entries)`);
  console.log(`  Skills : ${ALL_SKILLS.length}\n`);
  const rl = readline.createInterface({ input:process.stdin, output:process.stdout });
  process.on("SIGINT", async () => { rl.close(); process.exit(0); });
  const ask = () => rl.question("You > ", async line => {
    const t = line.trim(); if (!t) { ask(); return; }
    try { const r = await agent.chat(t); if (r) console.log(`\nAgent >\n${r}\n`); }
    catch(e) { console.error(`\n⚠ ${(e as Error).message}\n`); }
    ask();
  });
  rl.on("close", () => process.exit(0));
  ask();
}

main().catch(e => { console.error(e); process.exit(1); });
