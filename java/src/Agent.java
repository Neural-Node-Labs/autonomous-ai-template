package agent;

/*
 * =============================================================================
 * Agent.java
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Memory Agent
 * Version  : v1.0.2
 * Language : Java 17+
 * License  : MIT
 *
 * Full ReAct AI agent with 22 production SecOps skills (no mocks).
 * UI-aligned with cybersec-dashboard.jsx tool set.
 *
 * Skills:
 *   NETWORK  : port_scanner, dns_lookup, whois_lookup, ssl_cert_inspector,
 *              http_header_analyzer, network_recon, dns_security
 *   THREAT   : cve_lookup, ip_reputation, hash_lookup, ioc_extractor
 *   ANALYSIS : log_analyzer, vulnerability_scorer, vulnerability_assessment,
 *              web_app_scanner, api_security_audit, firewall_auditor
 *   CLOUD    : cloud_posture, container_scanner
 *   AUTH     : password_audit
 *   UTILITY  : summarizer, memory_writer
 *
 * Usage:
 *   export DEEPSEEK_API_KEY=sk-...
 *   export ABUSEIPDB_API_KEY=<optional>
 *   export VIRUSTOTAL_API_KEY=<optional>
 *   mvn package && java -jar target/omnikon-agent.jar
 * =============================================================================
 */

import memory.*;

import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;
import java.util.regex.*;
import java.util.stream.*;
import javax.net.ssl.*;

// ─────────────────────────────────────────────────────────────────────────────
// DeepSeek API
// ─────────────────────────────────────────────────────────────────────────────

final class DS {
    static final String URL   = "https://api.deepseek.com/v1/chat/completions";
    static final String MODEL = "deepseek-chat";
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15)).build();

    static String call(String system, List<Map<String,String>> msgs,
                       int maxTokens, double temp) throws IOException, InterruptedException {
        String key = System.getenv("DEEPSEEK_API_KEY");
        if (key == null || key.isBlank()) throw new IllegalStateException("DEEPSEEK_API_KEY not set");

        var all = new ArrayList<Map<String,String>>();
        all.add(Map.of("role","system","content",system));
        all.addAll(msgs);

        var sb = new StringBuilder("{\"model\":\"").append(MODEL)
            .append("\",\"max_tokens\":").append(maxTokens)
            .append(",\"temperature\":").append(temp)
            .append(",\"messages\":[");
        for (int i = 0; i < all.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"role\":\"").append(esc(all.get(i).get("role")))
              .append("\",\"content\":\"").append(esc(all.get(i).get("content"))).append("\"}");
        }
        sb.append("]}");

        var req = HttpRequest.newBuilder(URI.create(URL))
            .timeout(Duration.ofSeconds(90))
            .header("Content-Type","application/json")
            .header("Authorization","Bearer " + key)
            .POST(HttpRequest.BodyPublishers.ofString(sb.toString()))
            .build();

        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new IOException("DeepSeek " + resp.statusCode() + ": " +
                resp.body().substring(0, Math.min(200, resp.body().length())));

        var m = Pattern.compile("\"content\"\\s*:\\s*\"((?:[^\\\\\"]|\\\\.)*)\"").matcher(resp.body());
        String content = "";
        while (m.find()) content = m.group(1);
        return content.replace("\\n","\n").replace("\\\"","\"").replace("\\\\","\\");
    }

    static String esc(String s) {
        return s == null ? "" : s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");
    }

    private DS() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helper
// ─────────────────────────────────────────────────────────────────────────────

final class Http {
    record Resp(int status, Map<String,String> headers, String body) {}
    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();

    static Resp get(String url, Map<String,String> extraHeaders) {
        try {
            var builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("User-Agent","OMNIKON-SecOps/1.0.2")
                .GET();
            extraHeaders.forEach(builder::header);
            var resp = CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            var hdrs = new HashMap<String,String>();
            resp.headers().map().forEach((k,v) -> { if (!v.isEmpty()) hdrs.put(k.toLowerCase(), v.get(0)); });
            return new Resp(resp.statusCode(), hdrs, resp.body());
        } catch (Exception e) {
            return new Resp(0, Map.of(), "");
        }
    }

    static Resp get(String url) { return get(url, Map.of()); }
    private Http() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Skill system
// ─────────────────────────────────────────────────────────────────────────────

record SkillResult(String skill, boolean success, String output,
                   boolean storeToArchive, List<String> archiveTags) {
    SkillResult(String skill, boolean success, String output) {
        this(skill, success, output, false, List.of());
    }
    static SkillResult ok(String skill, String out, String... tags) {
        return new SkillResult(skill, true, out, tags.length > 0, List.of(tags));
    }
    static SkillResult err(String skill, String msg) {
        return new SkillResult(skill, false, "⚠ " + msg, false, List.of());
    }
}

interface Skill {
    String name(); String description(); String usage();
    List<String> triggerPatterns();
    SkillResult run(String args, MemoryManager mm);
}

// ── well-known service names ──────────────────────────────────────────────────
final class Svc {
    static final Map<Integer,String> MAP = Map.ofEntries(
        Map.entry(21,"ftp"), Map.entry(22,"ssh"), Map.entry(23,"telnet"),
        Map.entry(25,"smtp"), Map.entry(53,"dns"), Map.entry(80,"http"),
        Map.entry(110,"pop3"), Map.entry(143,"imap"), Map.entry(389,"ldap"),
        Map.entry(443,"https"), Map.entry(445,"smb"), Map.entry(3306,"mysql"),
        Map.entry(3389,"rdp"), Map.entry(5432,"postgres"), Map.entry(6379,"redis"),
        Map.entry(8080,"http-alt"), Map.entry(8443,"https-alt"),
        Map.entry(27017,"mongodb"), Map.entry(5900,"vnc"), Map.entry(11211,"memcached")
    );
    static String name(int port) { return MAP.getOrDefault(port, "unknown"); }
    private Svc() {}
}

// ── TCP scan helper ───────────────────────────────────────────────────────────
final class TcpScan {
    record PortResult(int port, boolean open, String banner) {}

    static PortResult probe(String host, int port, int timeoutMs) {
        try (var s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(400);
            String banner = "";
            try {
                byte[] buf = new byte[256];
                int n = s.getInputStream().read(buf);
                if (n > 0) banner = new String(buf, 0, Math.min(n, 80)).trim();
            } catch (Exception ignored) {}
            return new PortResult(port, true, banner);
        } catch (Exception e) {
            return new PortResult(port, false, "");
        }
    }

    static List<PortResult> scanPorts(String host, List<Integer> ports, int workers, int timeoutMs) {
        var exec = Executors.newFixedThreadPool(workers);
        var futs = ports.stream()
            .map(p -> exec.submit(() -> probe(host, p, timeoutMs)))
            .collect(Collectors.toList());
        var results = futs.stream().map(f -> {
            try { return f.get(5, TimeUnit.SECONDS); }
            catch (Exception e) { return new PortResult(0, false, ""); }
        }).filter(r -> r.port() > 0 && r.open()).collect(Collectors.toList());
        exec.shutdownNow();
        return results;
    }

    private TcpScan() {}
}

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK SKILLS
// ═════════════════════════════════════════════════════════════════════════════

record PortScannerSkill() implements Skill {
    public String name()        { return "port_scanner"; }
    public String description() { return "TCP connect scan on host:ports"; }
    public String usage()       { return "port_scanner <host> <ports>  e.g. 192.168.1.1 22,80,443"; }
    public List<String> triggerPatterns() { return List.of("port scan","scan ports","open ports"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts = args.trim().split("\\s+", 2);
        if (parts.length < 2) return SkillResult.err(name(), "Usage: " + usage());
        String host = parts[0]; String portSpec = parts[1];
        List<Integer> ports = new ArrayList<>();
        for (var seg : portSpec.split(",")) {
            seg = seg.strip();
            if (seg.contains("-")) {
                var ab = seg.split("-"); int a = Integer.parseInt(ab[0]), b = Integer.parseInt(ab[1]);
                for (int p = a; p <= Math.min(b, a+499); p++) ports.add(p);
            } else ports.add(Integer.parseInt(seg));
        }
        if (ports.size() > 500) return SkillResult.err(name(), "Max 500 ports");
        String ip;
        try { ip = InetAddress.getByName(host).getHostAddress(); }
        catch (UnknownHostException e) { return SkillResult.err(name(), "Cannot resolve " + host); }

        var open = TcpScan.scanPorts(ip, ports, 50, 1200);
        open.sort(Comparator.comparingInt(TcpScan.PortResult::port));
        if (open.isEmpty())
            return SkillResult.ok(name(), "**Port Scan** " + host + " — no open ports", "port_scan", host);

        var sb = new StringBuilder("**Port Scan** " + host + " (" + ip + ") — " + open.size() + " open\n\n");
        for (var r : open) {
            sb.append(String.format("  %5d/tcp  OPEN  %-12s%s%n",
                r.port(), Svc.name(r.port()), r.banner().isEmpty() ? "" : " — `" + r.banner() + "`"));
        }
        return SkillResult.ok(name(), sb.toString(), "port_scan", host, "open:" + open.size());
    }
}

record DnsLookupSkill() implements Skill {
    public String name()        { return "dns_lookup"; }
    public String description() { return "DNS resolution: A, PTR, all record types via dig"; }
    public String usage()       { return "dns_lookup <hostname|ip> [A|PTR|MX|TXT|NS]"; }
    public List<String> triggerPatterns() { return List.of("dns lookup","resolve hostname","dns record"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts  = args.trim().split("\\s+");
        if (parts.length < 1 || parts[0].isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String target = parts[0]; String rtype = parts.length > 1 ? parts[1].toUpperCase() : "A";
        var sb = new StringBuilder("**DNS Lookup** `" + target + "` (" + rtype + ")\n\n");
        try {
            if ("PTR".equals(rtype)) {
                var addr = InetAddress.getByName(target);
                sb.append("  PTR  ").append(addr.getCanonicalHostName()).append("\n");
            } else if ("A".equals(rtype) || "AAAA".equals(rtype)) {
                for (var a : InetAddress.getAllByName(target))
                    sb.append("  ").append(rtype).append("    ").append(a.getHostAddress()).append("\n");
            } else {
                // Fall back to dig
                var r = Runtime.getRuntime().exec(new String[]{"dig","+short",rtype,target});
                String out = new String(r.getInputStream().readAllBytes());
                for (var line : out.strip().split("\n"))
                    if (!line.isBlank()) sb.append("  ").append(rtype).append("    ").append(line.strip()).append("\n");
            }
        } catch (Exception e) { return SkillResult.err(name(), "DNS error: " + e.getMessage()); }
        return SkillResult.ok(name(), sb.toString(), "dns", target);
    }
}

record WhoisLookupSkill() implements Skill {
    public String name()        { return "whois_lookup"; }
    public String description() { return "WHOIS registration data via TCP port 43"; }
    public String usage()       { return "whois_lookup <domain|ip>"; }
    public List<String> triggerPatterns() { return List.of("whois","domain registration","ip owner"); }
    public SkillResult run(String args, MemoryManager mm) {
        String target = args.trim();
        if (target.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        boolean isIp = target.matches("(\\d{1,3}\\.){3}\\d{1,3}");
        String server = isIp ? "whois.arin.net" : getWhoisServer(target);
        try {
            String raw = whoisQuery(server, target);
            if ("whois.iana.org".equals(server)) {
                for (var line : raw.lines().toList()) {
                    if (line.strip().toLowerCase().startsWith("whois:")) {
                        String refer = line.split(":",2)[1].strip();
                        try { raw = whoisQuery(refer, target); } catch (Exception ignored) {}
                        break;
                    }
                }
            }
            var important = new LinkedHashMap<String,String>();
            for (var line : raw.lines().toList()) {
                for (var key : List.of("Registrar","Creation Date","Expiry Date","Updated Date",
                        "Name Server","Status","Organization","OrgName","Country","NetRange")) {
                    if (line.strip().toLowerCase().startsWith(key.toLowerCase()+":") && !important.containsKey(key))
                        important.put(key, line.split(":",2)[1].strip());
                }
            }
            var sb = new StringBuilder("**WHOIS** `" + target + "` (via " + server + ")\n\n");
            if (important.isEmpty()) sb.append(raw.substring(0, Math.min(800, raw.length())));
            else important.forEach((k,v) -> sb.append(String.format("  %-22s: %s%n", k, v)));
            return SkillResult.ok(name(), sb.toString(), "whois", target);
        } catch (Exception e) { return SkillResult.err(name(), "WHOIS failed: " + e.getMessage()); }
    }
    private String getWhoisServer(String domain) {
        String tld = domain.contains(".") ? domain.substring(domain.lastIndexOf(".")+1).toLowerCase() : "default";
        return switch(tld) {
            case "com","net" -> "whois.verisign-grs.com";
            case "org" -> "whois.pir.org";
            case "io"  -> "whois.nic.io";
            case "uk"  -> "whois.nic.uk";
            default -> "whois.iana.org";
        };
    }
    private String whoisQuery(String server, String target) throws Exception {
        try (var s = new Socket(server, 43, null, 0)) {
            s.setSoTimeout(10_000);
            s.getOutputStream().write((target + "\r\n").getBytes());
            return new String(s.getInputStream().readAllBytes());
        }
    }
}

record SslCertInspectorSkill() implements Skill {
    public String name()        { return "ssl_cert_inspector"; }
    public String description() { return "Inspect TLS certificate: expiry, issuer, SANs, cipher"; }
    public String usage()       { return "ssl_cert_inspector <hostname> [port]"; }
    public List<String> triggerPatterns() { return List.of("ssl cert","tls certificate","certificate expiry"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts = args.trim().split("\\s+");
        if (parts[0].isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String host = parts[0]; int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 443;
        try {
            var ctx = SSLContext.getDefault();
            var factory = ctx.getSocketFactory();
            try (var sock = (SSLSocket) factory.createSocket(host, port)) {
                sock.setSoTimeout(10_000);
                sock.startHandshake();
                var session = sock.getSession();
                var cert    = (java.security.cert.X509Certificate) session.getPeerCertificates()[0];
                var now     = Instant.now();
                var expiry  = cert.getNotAfter().toInstant();
                var start   = cert.getNotBefore().toInstant();
                long daysLeft = Duration.between(now, expiry).toDays();
                String tag  = daysLeft < 0 ? "[CRITICAL] EXPIRED" : daysLeft < 30 ? "[WARN] expiring soon" : "valid";
                String cipher = session.getCipherSuite();
                String proto  = session.getProtocol();
                var sans = new ArrayList<String>();
                try {
                    var sanExt = cert.getSubjectAlternativeNames();
                    if (sanExt != null) for (var san : sanExt)
                        if ((Integer)san.get(0) == 2) sans.add(san.get(1).toString());
                } catch (Exception ignored) {}
                var sb = new StringBuilder("**SSL Certificate** `" + host + ":" + port + "`\n\n");
                sb.append("  TLS Version : ").append(proto).append("\n");
                sb.append("  Cipher      : ").append(cipher).append("\n");
                sb.append("  CN          : ").append(cert.getSubjectX500Principal().getName()).append("\n");
                sb.append("  Issuer      : ").append(cert.getIssuerX500Principal().getName()).append("\n");
                sb.append("  Valid From  : ").append(start.toString().substring(0,10)).append("\n");
                sb.append("  Expiry      : ").append(expiry.toString().substring(0,10))
                  .append(" — ").append(daysLeft).append("d left [").append(tag).append("]\n");
                if (!sans.isEmpty())
                    sb.append("  SANs        : ").append(String.join(", ", sans.subList(0, Math.min(10, sans.size())))).append("\n");
                var tags = new ArrayList<>(List.of("ssl_cert", host));
                if (daysLeft < 0) tags.add("expired_cert");
                else if (daysLeft < 30) tags.add("expiring_cert");
                return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
            }
        } catch (Exception e) { return SkillResult.err(name(), "TLS error: " + e.getMessage()); }
    }
}

record HttpHeaderAnalyzerSkill() implements Skill {
    public String name()        { return "http_header_analyzer"; }
    public String description() { return "Fetch HTTP headers and audit security posture"; }
    public String usage()       { return "http_header_analyzer <url>"; }
    public List<String> triggerPatterns() { return List.of("http headers","security headers","check hsts"); }
    public SkillResult run(String args, MemoryManager mm) {
        String url = args.trim();
        if (url.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        if (!url.startsWith("http")) url = "https://" + url;
        var resp = Http.get(url);
        if (resp.status() == 0) return SkillResult.err(name(), "Cannot connect to " + url);
        var HDRS = List.of(
            new String[]{"strict-transport-security","HSTS","critical"},
            new String[]{"content-security-policy","CSP","critical"},
            new String[]{"x-frame-options","X-Frame","critical"},
            new String[]{"x-content-type-options","XCTO","critical"},
            new String[]{"referrer-policy","Ref-Policy","warn"}
        );
        var missing = new ArrayList<String>();
        var sb = new StringBuilder("**HTTP Header Analysis** `" + url + "`\n\n");
        sb.append("  Status  : ").append(resp.status()).append("\n");
        sb.append("  Server  : ").append(resp.headers().getOrDefault("server","hidden")).append("\n");
        sb.append("  Powered : ").append(resp.headers().getOrDefault("x-powered-by","hidden")).append("\n\n");
        sb.append("  Security Headers:\n");
        for (var h : HDRS) {
            String val = resp.headers().get(h[0]);
            boolean present = val != null;
            String flag = present ? "✓" : ("critical".equals(h[2]) ? "✗ [CRITICAL]" : "✗ [INFO]");
            sb.append(String.format("    %s %-15s %s%n", flag, h[1], present ? val.substring(0,Math.min(80,val.length())) : "absent"));
            if (!present && "critical".equals(h[2])) missing.add(h[1]);
        }
        if (!missing.isEmpty()) sb.append("\n  [CRITICAL] Missing: ").append(String.join(", ", missing));
        var tags = new ArrayList<>(List.of("http_headers"));
        if (!missing.isEmpty()) tags.add("missing_headers");
        return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
    }
}

record NetworkReconSkill() implements Skill {
    public String name()        { return "network_recon"; }
    public String description() { return "Network recon: CIDR host discovery, service sweep"; }
    public String usage()       { return "network_recon <cidr_or_host>  e.g. 192.168.1.0/24"; }
    public List<String> triggerPatterns() { return List.of("network recon","host discovery","cidr scan","topology"); }
    public SkillResult run(String args, MemoryManager mm) {
        String target = args.trim();
        if (target.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        List<String> ips = new ArrayList<>();
        if (target.contains("/")) {
            try {
                var network = target.split("/");
                var base    = InetAddress.getByName(network[0]);
                int prefix  = Integer.parseInt(network[1]);
                long count  = (long) Math.pow(2, 32 - prefix);
                byte[] addr = base.getAddress();
                long baseNum = 0;
                for (byte b : addr) baseNum = (baseNum << 8) | (b & 0xFF);
                // Clear host bits
                long mask = 0xFFFFFFFFL << (32 - prefix) & 0xFFFFFFFFL;
                baseNum  &= mask;
                for (long i = 1; i < Math.min(count - 1, 64); i++) {
                    long ip = baseNum + i;
                    ips.add(((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF));
                }
            } catch (Exception e) { return SkillResult.err(name(), "CIDR parse error: " + e.getMessage()); }
        } else {
            try { ips.add(InetAddress.getByName(target).getHostAddress()); }
            catch (Exception e) { return SkillResult.err(name(), "Cannot resolve: " + e.getMessage()); }
        }
        var PROBE_PORTS = List.of(22, 80, 443, 445, 3389);
        record Host(String ip, String hostname, List<Integer> ports) {}
        var exec  = Executors.newFixedThreadPool(30);
        var futs  = ips.stream().map(ip -> exec.submit(() -> {
            var open = TcpScan.scanPorts(ip, PROBE_PORTS, 5, 800);
            if (open.isEmpty()) {
                try { if (!InetAddress.getByName(ip).isReachable(500)) return null; }
                catch (Exception e) { return null; }
            }
            String hostname = "";
            try { hostname = InetAddress.getByName(ip).getCanonicalHostName(); } catch (Exception ignored) {}
            return new Host(ip, hostname.equals(ip) ? "" : hostname, open.stream().map(TcpScan.PortResult::port).collect(Collectors.toList()));
        })).collect(Collectors.toList());
        exec.shutdown();
        var liveHosts = futs.stream().map(f -> {
            try { return f.get(10, TimeUnit.SECONDS); } catch (Exception e) { return null; }
        }).filter(Objects::nonNull).collect(Collectors.toList());
        var sb = new StringBuilder("**Network Recon** `" + target + "` — scanned " + ips.size() + " host(s)\n\n");
        if (liveHosts.isEmpty()) { sb.append("  No live hosts discovered.\n"); }
        else {
            sb.append("  **Live Hosts (").append(liveHosts.size()).append("):**\n");
            for (var h : liveHosts) {
                sb.append("    ").append(String.format("%-17s", h.ip()));
                if (!h.hostname().isEmpty()) sb.append(" (").append(h.hostname()).append(")");
                sb.append("\n");
                if (!h.ports().isEmpty())
                    sb.append("      Services: ").append(h.ports().stream().map(p -> Svc.name(p)+"("+p+")").collect(Collectors.joining(", "))).append("\n");
            }
            boolean hasRisky = liveHosts.stream().anyMatch(h -> h.ports().stream().anyMatch(p -> p == 23 || p == 21 || p == 3389));
            sb.append("\n  Risk: [").append(hasRisky ? "HIGH" : "MEDIUM").append("]");
        }
        return SkillResult.ok(name(), sb.toString(), "network_recon", target);
    }
}

record DnsSecuritySkill() implements Skill {
    public String name()        { return "dns_security"; }
    public String description() { return "DNS security: DNSSEC, zone transfer, SPF/DKIM/DMARC"; }
    public String usage()       { return "dns_security <domain>"; }
    public List<String> triggerPatterns() { return List.of("dns security","dnssec","zone transfer","spf dkim","email security"); }
    public SkillResult run(String args, MemoryManager mm) {
        String domain = args.trim().toLowerCase();
        if (domain.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        var sb = new StringBuilder("**DNS Security Analysis** `" + domain + "`\n\n");
        // A records
        try {
            var addrs = InetAddress.getAllByName(domain);
            sb.append("  A records: ").append(Arrays.stream(addrs).map(InetAddress::getHostAddress).collect(Collectors.joining(", "))).append("\n");
        } catch (Exception e) { sb.append("  A records: resolve failed\n"); }
        // dig for MX, TXT, NS, DMARC, DKIM
        boolean spf = false, dmarc = false, dkim = false, ztVuln = false;
        List<String> ns = new ArrayList<>();
        for (String[] cmd : new String[][]{
            {"dig","+short","MX",domain},
            {"dig","+short","TXT",domain},
            {"dig","+short","NS",domain},
            {"dig","+short","TXT","_dmarc."+domain},
            {"dig","+short","TXT","default._domainkey."+domain},
        }) {
            try {
                var r = Runtime.getRuntime().exec(cmd);
                String out = new String(r.getInputStream().readAllBytes()).strip();
                String type = cmd[2];
                if (!out.isEmpty()) {
                    if ("TXT".equals(type) && (cmd[3].equals(domain)))
                        spf = out.toLowerCase().contains("v=spf1");
                    if ("NS".equals(type)) ns.addAll(Arrays.asList(out.split("\n")));
                    if ("TXT".equals(type) && cmd[3].startsWith("_dmarc"))
                        dmarc = out.toLowerCase().contains("v=dmarc1");
                    if ("TXT".equals(type) && cmd[3].startsWith("default._domainkey"))
                        dkim = out.toLowerCase().contains("v=dkim1");
                }
            } catch (Exception ignored) {}
        }
        // Zone transfer
        if (!ns.isEmpty()) {
            try {
                var r = Runtime.getRuntime().exec(new String[]{"dig","AXFR",domain,"@",ns.get(0).strip().replaceAll("\\.$","")});
                r.waitFor(8, TimeUnit.SECONDS);
                String out = new String(r.getInputStream().readAllBytes()).strip();
                ztVuln = out.lines().count() > 5;
            } catch (Exception ignored) {}
        }
        sb.append("\n  Email Security:\n");
        sb.append("    SPF   : ").append(spf  ? "✓ present" : "✗ [WARN] missing").append("\n");
        sb.append("    DMARC : ").append(dmarc ? "✓ present" : "✗ [WARN] missing").append("\n");
        sb.append("    DKIM  : ").append(dkim  ? "✓ present" : "⚠ default selector not found").append("\n");
        sb.append("\n  Zone Transfer: ").append(ztVuln ? "[CRITICAL] ALLOWED" : "✓ Restricted").append("\n");
        String risk = ztVuln ? "HIGH" : (!spf || !dmarc) ? "MEDIUM" : "LOW";
        sb.append("  Risk Level  : [").append(risk).append("]\n");
        var tags = new ArrayList<>(List.of("dns_security", domain));
        if (ztVuln) tags.add("zone_transfer");
        if (!spf)  tags.add("missing_spf");
        return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE SKILLS
// ═════════════════════════════════════════════════════════════════════════════

record CveLookupSkill() implements Skill {
    public String name()        { return "cve_lookup"; }
    public String description() { return "CVE details from NVD/NIST public API (no key needed)"; }
    public String usage()       { return "cve_lookup <CVE-YYYY-NNNNN>"; }
    public List<String> triggerPatterns() { return List.of("cve lookup","vulnerability details","check cve","nvd"); }
    public SkillResult run(String args, MemoryManager mm) {
        String cveId = args.trim().toUpperCase();
        if (!cveId.matches("CVE-\\d{4}-\\d+")) return SkillResult.err(name(), "Invalid CVE format");
        var resp = Http.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveId);
        if (resp.status() == 0) return SkillResult.err(name(), "NVD API unreachable");
        try {
            // Simple JSON extraction without full parser
            String body = resp.body();
            var descM = Pattern.compile("\"lang\"\\s*:\\s*\"en\"\\s*,\\s*\"value\"\\s*:\\s*\"([^\"]{0,400})\"").matcher(body);
            String desc = descM.find() ? descM.group(1) : "No description";
            var scoreM = Pattern.compile("\"baseScore\"\\s*:\\s*([\\d.]+)").matcher(body);
            String score = scoreM.find() ? scoreM.group(1) : "N/A";
            var sevM = Pattern.compile("\"baseSeverity\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
            String sev = sevM.find() ? sevM.group(1) : "N/A";
            double scoreD = 0;
            try { scoreD = Double.parseDouble(score); } catch (Exception ignored) {}
            String tag = scoreD >= 9.0 ? "[CRITICAL]" : scoreD >= 7.0 ? "[HIGH]" : scoreD >= 4.0 ? "[MEDIUM]" : "[LOW]";
            var sb = new StringBuilder("**CVE** `" + cveId + "` " + tag + "\n\n");
            sb.append("  CVSS Score  : ").append(score).append(" (").append(sev).append(")\n");
            sb.append("  Description : ").append(desc, 0, Math.min(400, desc.length())).append("\n");
            return SkillResult.ok(name(), sb.toString(), "cve", cveId, sev.toLowerCase());
        } catch (Exception e) { return SkillResult.err(name(), "Parse error: " + e.getMessage()); }
    }
}

record IpReputationSkill() implements Skill {
    public String name()        { return "ip_reputation"; }
    public String description() { return "IP reputation via AbuseIPDB + DNSBL checks"; }
    public String usage()       { return "ip_reputation <ip_address>"; }
    public List<String> triggerPatterns() { return List.of("ip reputation","is this ip malicious","check ip"); }
    public SkillResult run(String args, MemoryManager mm) {
        String ip = args.trim();
        if (!ip.matches("(\\d{1,3}\\.){3}\\d{1,3}")) return SkillResult.err(name(), "Invalid IP: " + ip);
        var sb = new StringBuilder("**IP Reputation** `" + ip + "`\n\n");
        String abuseKey = System.getenv("ABUSEIPDB_API_KEY");
        if (abuseKey != null && !abuseKey.isBlank()) {
            var resp = Http.get("https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90",
                Map.of("Key", abuseKey, "Accept","application/json"));
            if (resp.status() == 200) {
                var confM = Pattern.compile("\"abuseConfidenceScore\"\\s*:\\s*(\\d+)").matcher(resp.body());
                var rptM  = Pattern.compile("\"totalReports\"\\s*:\\s*(\\d+)").matcher(resp.body());
                var ctryM = Pattern.compile("\"countryCode\"\\s*:\\s*\"([^\"]+)\"").matcher(resp.body());
                int conf = confM.find() ? Integer.parseInt(confM.group(1)) : 0;
                String rpts = rptM.find() ? rptM.group(1) : "0";
                String ctry = ctryM.find() ? ctryM.group(1) : "??";
                String tag  = conf >= 75 ? "[CRITICAL]" : conf >= 25 ? "[WARN]" : "[CLEAN]";
                sb.append("  AbuseIPDB: ").append(tag).append(" confidence=").append(conf).append("% reports=").append(rpts).append(" country=").append(ctry).append("\n");
            }
        } else sb.append("  AbuseIPDB: set ABUSEIPDB_API_KEY for live scoring\n");
        // DNSBL
        String[] octets = ip.split("\\.");
        String rev = octets[3]+"."+octets[2]+"."+octets[1]+"."+octets[0];
        var listed = new ArrayList<String>();
        for (String bl : new String[]{"zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net"}) {
            try { InetAddress.getByName(rev+"."+bl); listed.add(bl); } catch (Exception ignored) {}
        }
        sb.append(listed.isEmpty()
            ? "  DNSBL: ✓ not listed on 3 checked blocklists\n"
            : "  [CRITICAL] DNSBL listed on: " + String.join(", ", listed) + "\n");
        var tags = new ArrayList<>(List.of("ip_reputation", ip));
        if (!listed.isEmpty()) tags.add("blacklisted");
        return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
    }
}

record HashLookupSkill() implements Skill {
    public String name()        { return "hash_lookup"; }
    public String description() { return "Hash a string/file (MD5/SHA1/SHA256) + optional VirusTotal"; }
    public String usage()       { return "hash_lookup <text_or_filepath> [md5|sha1|sha256]"; }
    public List<String> triggerPatterns() { return List.of("hash lookup","virustotal","file hash","malware hash"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String target = args.trim().split("\\s+")[0];
        byte[] data;
        try {
            var p = Path.of(target);
            data = p.toFile().exists() ? Files.readAllBytes(p) : target.getBytes();
        } catch (Exception e) { data = target.getBytes(); }
        try {
            String md5    = hex(MessageDigest.getInstance("MD5").digest(data));
            String sha1   = hex(MessageDigest.getInstance("SHA-1").digest(data));
            String sha256 = hex(MessageDigest.getInstance("SHA-256").digest(data));
            var sb = new StringBuilder("**Hash Lookup**\n\n");
            sb.append("  MD5    : ").append(md5).append("\n");
            sb.append("  SHA1   : ").append(sha1).append("\n");
            sb.append("  SHA256 : ").append(sha256).append("\n");
            String vtKey = System.getenv("VIRUSTOTAL_API_KEY");
            if (vtKey != null && !vtKey.isBlank()) {
                var resp = Http.get("https://www.virustotal.com/api/v3/files/"+sha256, Map.of("x-apikey",vtKey));
                if (resp.status() == 404) sb.append("  VT     : not found in database\n");
                else if (resp.status() == 200) {
                    var malM = Pattern.compile("\"malicious\"\\s*:\\s*(\\d+)").matcher(resp.body());
                    int mal  = malM.find() ? Integer.parseInt(malM.group(1)) : 0;
                    String tag = mal > 5 ? "[CRITICAL]" : mal > 0 ? "[WARN]" : "[CLEAN]";
                    sb.append("  VT     : ").append(tag).append(" ").append(mal).append(" engines flagged malicious\n");
                }
            } else sb.append("  VT     : set VIRUSTOTAL_API_KEY for live lookup\n");
            return SkillResult.ok(name(), sb.toString(), "hash", sha256.substring(0,16));
        } catch (Exception e) { return SkillResult.err(name(), e.getMessage()); }
    }
    private static String hex(byte[] b) {
        var sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x",x));
        return sb.toString();
    }
}

record IocExtractorSkill() implements Skill {
    public String name()        { return "ioc_extractor"; }
    public String description() { return "Extract IOCs: IPs, domains, hashes, CVEs, emails, URLs"; }
    public String usage()       { return "ioc_extractor <text>"; }
    public List<String> triggerPatterns() { return List.of("extract ioc","find indicators","ioc extract"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        var patterns = new LinkedHashMap<String,Pattern>();
        patterns.put("IPv4",   Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b"));
        patterns.put("Domain", Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+(?:com|net|org|io|gov|edu|uk|de)\\b"));
        patterns.put("URL",    Pattern.compile("https?://[^\\s\"'<>]{8,200}"));
        patterns.put("Email",  Pattern.compile("\\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}\\b"));
        patterns.put("MD5",    Pattern.compile("\\b[0-9a-fA-F]{32}\\b"));
        patterns.put("SHA256", Pattern.compile("\\b[0-9a-fA-F]{64}\\b"));
        patterns.put("CVE",    Pattern.compile("(?i)\\bCVE-\\d{4}-\\d{4,}\\b"));
        var results = new LinkedHashMap<String,List<String>>();
        for (var e : patterns.entrySet()) {
            var m = e.getValue().matcher(args);
            var found = new LinkedHashSet<String>();
            while (m.find()) found.add(m.group());
            if (!found.isEmpty()) results.put(e.getKey(), new ArrayList<>(found));
        }
        if (results.isEmpty()) return SkillResult.ok(name(), "No IOCs found.");
        int total = results.values().stream().mapToInt(List::size).sum();
        var sb = new StringBuilder("**IOC Extraction** — " + total + " indicators found\n\n");
        results.forEach((type, items) -> {
            sb.append("  ").append(type).append(" (").append(items.size()).append("):\n");
            items.stream().limit(20).forEach(i -> sb.append("    ").append(i).append("\n"));
            if (items.size() > 20) sb.append("    … and ").append(items.size()-20).append(" more\n");
        });
        return SkillResult.ok(name(), sb.toString(), "ioc_extraction", "count:"+total);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ANALYSIS SKILLS
// ═════════════════════════════════════════════════════════════════════════════

record LogAnalyzerSkill() implements Skill {
    public String name()        { return "log_analyzer"; }
    public String description() { return "Deep log analysis: brute-force, SQLi, XSS, recon patterns"; }
    public String usage()       { return "log_analyzer <log text>"; }
    public List<String> triggerPatterns() { return List.of("analyze log","parse log","check logs","siem"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        var lines   = args.strip().split("\n");
        var ipPat   = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        var failPat = Pattern.compile("(?i)(FAILED_LOGIN|authentication failure|invalid password)");
        var sqliPat = Pattern.compile("(?i)(UNION\\s+SELECT|OR\\s+1=1|DROP\\s+TABLE|xp_cmdshell)");
        var xssPat  = Pattern.compile("(?i)(<script|javascript:|onerror=)");
        var pathPat = Pattern.compile("(?i)(\\.\\./|/etc/passwd)");
        var tsPat   = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}");
        var failures = new HashMap<String,Integer>();
        var successes= new HashMap<String,Integer>();
        var sqli = new ArrayList<String>(); var xss = new ArrayList<String>(); var pathT = new ArrayList<String>();
        var ips  = new LinkedHashSet<String>(); var ts = new LinkedHashSet<String>();
        for (var line : lines) {
            var im = ipPat.matcher(line); while (im.find()) ips.add(im.group());
            var tm = tsPat.matcher(line); while (tm.find()) ts.add(tm.group());
            if (failPat.matcher(line).find()) { var m = ipPat.matcher(line); while(m.find()) failures.merge(m.group(),1,Integer::sum); }
            if (Pattern.compile("(?i)(LOGIN_SUCCESS|authenticated)").matcher(line).find()) {var m=ipPat.matcher(line);while(m.find())successes.merge(m.group(),1,Integer::sum);}
            if (sqliPat.matcher(line).find()) sqli.add(line);
            if (xssPat.matcher(line).find())  xss.add(line);
            if (pathPat.matcher(line).find()) pathT.add(line);
        }
        var sb = new StringBuilder("**Log Analysis** — " + lines.length + " lines, " + ips.size() + " unique IPs\n\n");
        if (!ts.isEmpty()) { var tsList = new ArrayList<>(ts); sb.append("  Time range: ").append(tsList.get(0)).append(" → ").append(tsList.get(tsList.size()-1)).append("\n"); }
        var findings = new ArrayList<String>();
        failures.forEach((ip,cnt) -> {
            String succ = successes.containsKey(ip) ? " ("+successes.get(ip)+" success after)" : "";
            findings.add((cnt>=5?"[CRITICAL]":"[WARN]") + " Brute-force: " + cnt + " failures from " + ip + succ);
        });
        if (!sqli.isEmpty())  findings.add("[CRITICAL] SQL Injection: " + sqli.size() + " lines — " + sqli.get(0).substring(0,Math.min(100,sqli.get(0).length())));
        if (!xss.isEmpty())   findings.add("[CRITICAL] XSS attempts: " + xss.size() + " lines");
        if (!pathT.isEmpty()) findings.add("[HIGH] Path traversal: " + pathT.size() + " lines");
        if (findings.isEmpty()) sb.append("  ✓ No anomalies detected\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f -> sb.append("    ").append(f).append("\n")); }
        var tags = new ArrayList<>(List.of("log_analysis"));
        if (!sqli.isEmpty()) tags.add("sql_injection"); if (!xss.isEmpty()) tags.add("xss");
        if (!failures.isEmpty()) tags.add("brute_force");
        return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
    }
}

record VulnerabilityScorerSkill() implements Skill {
    public String name()        { return "vulnerability_scorer"; }
    public String description() { return "CVSS v3.1 scoring and OWASP risk rating via AI"; }
    public String usage()       { return "vulnerability_scorer <finding description>"; }
    public List<String> triggerPatterns() { return List.of("score vulnerability","cvss score","risk rating"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        try {
            String raw = DS.call(
                "You are a CVSS v3.1 expert. Return ONLY JSON: {\"cvss_score\":7.5,\"cvss_severity\":\"HIGH\",\"cvss_vector\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N\",\"owasp_category\":\"A03:2021\",\"attack_vector\":\"Network\",\"confidentiality_impact\":\"High\",\"integrity_impact\":\"None\",\"availability_impact\":\"None\",\"remediation_priority\":\"Critical\",\"recommended_fix\":\"Parameterise all queries\"}",
                List.of(Map.of("role","user","content","Score: " + args.substring(0,Math.min(2000,args.length())))),
                512, 0.1);
            var jm = Pattern.compile("\\{[\\s\\S]+\\}").matcher(raw);
            if (!jm.find()) return SkillResult.err(name(), "Could not parse scoring response");
            String json = jm.group();
            var extract = (java.util.function.Function<String,String>) key -> {
                var m = Pattern.compile("\""+key+"\"\\s*:\\s*\"?([^\"\\},]+)\"?").matcher(json);
                return m.find() ? m.group(1).strip() : "N/A";
            };
            var sb = new StringBuilder("**Vulnerability Score**\n\n");
            sb.append("  CVSS Score  : ").append(extract.apply("cvss_score")).append(" (").append(extract.apply("cvss_severity")).append(")\n");
            sb.append("  CVSS Vector : ").append(extract.apply("cvss_vector")).append("\n");
            sb.append("  OWASP       : ").append(extract.apply("owasp_category")).append("\n");
            sb.append("  C/I/A       : ").append(extract.apply("confidentiality_impact")).append("/").append(extract.apply("integrity_impact")).append("/").append(extract.apply("availability_impact")).append("\n");
            sb.append("  Priority    : ").append(extract.apply("remediation_priority")).append("\n");
            sb.append("  Fix         : ").append(extract.apply("recommended_fix")).append("\n");
            return SkillResult.ok(name(), sb.toString(), "vuln_score", extract.apply("cvss_severity").toLowerCase());
        } catch (Exception e) { return SkillResult.err(name(), "Scoring failed: " + e.getMessage()); }
    }
}

record VulnerabilityAssessmentSkill() implements Skill {
    public String name()        { return "vulnerability_assessment"; }
    public String description() { return "Full assessment: port scan + service fingerprint + NVD CVE correlation"; }
    public String usage()       { return "vulnerability_assessment <host>"; }
    public List<String> triggerPatterns() { return List.of("vulnerability assessment","full scan","assess target","pentest"); }
    public SkillResult run(String args, MemoryManager mm) {
        String host = args.trim();
        if (host.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String ip;
        try { ip = InetAddress.getByName(host).getHostAddress(); }
        catch (Exception e) { return SkillResult.err(name(), "Cannot resolve " + host); }
        var COMMON = List.of(21,22,23,25,53,80,110,143,389,443,445,3306,3389,5432,6379,8080,8443,27017);
        var open = TcpScan.scanPorts(ip, COMMON, 30, 1200);
        open.sort(Comparator.comparingInt(TcpScan.PortResult::port));
        var allCves = new ArrayList<String>();
        var seen = new HashSet<String>();
        for (var r : open.subList(0, Math.min(5, open.size()))) {
            String svc = Svc.name(r.port());
            if (seen.contains(svc) || "unknown".equals(svc)) continue;
            seen.add(svc);
            try {
                var resp = Http.get("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + svc + "&resultsPerPage=3");
                if (resp.status() == 200) {
                    var m = Pattern.compile("\"id\"\\s*:\\s*\"(CVE-[^\"]+)\"").matcher(resp.body());
                    while (m.find() && allCves.size() < 8) allCves.add(m.group(1) + " (" + svc + ")");
                }
                Thread.sleep(200); // NVD rate limit
            } catch (Exception ignored) {}
        }
        boolean hasCritical = false; // simplified — check in real impl
        String risk = open.stream().anyMatch(r -> r.port() == 23 || r.port() == 21) ? "critical" :
                      !allCves.isEmpty() ? "high" : open.isEmpty() ? "low" : "medium";
        var sb = new StringBuilder("**Vulnerability Assessment** `" + host + "` (" + ip + ")\n\n");
        sb.append("  Risk Level  : [").append(risk.toUpperCase()).append("]\n");
        sb.append("  Open Ports  : ").append(open.size()).append("\n");
        sb.append("  CVEs Found  : ").append(allCves.size()).append("\n\n");
        if (!open.isEmpty()) {
            sb.append("  **Open Ports:**\n");
            for (var r : open) sb.append(String.format("    %5d/tcp  %-12s%s%n", r.port(), Svc.name(r.port()), r.banner().isEmpty()?"":(" — `"+r.banner()+"`")));
        }
        if (!allCves.isEmpty()) {
            sb.append("\n  **Related CVEs (NVD):**\n");
            allCves.forEach(c -> sb.append("    ").append(c).append("\n"));
        }
        return SkillResult.ok(name(), sb.toString(), "vuln_assessment", host, risk);
    }
}

record WebAppScannerSkill() implements Skill {
    public String name()        { return "web_app_scanner"; }
    public String description() { return "OWASP Top 10 active scan: SQLi probe, XSS probe, sensitive paths"; }
    public String usage()       { return "web_app_scanner <url> [auth_header]"; }
    public List<String> triggerPatterns() { return List.of("web app scan","owasp scan","web scan","xss scan"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts = args.trim().split("\\s+", 2);
        if (parts[0].isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String url = parts[0].startsWith("http") ? parts[0] : "https://" + parts[0];
        Map<String,String> auth = parts.length > 1 ? Map.of("Authorization", parts[1]) : Map.of();
        var resp = Http.get(url, auth);
        if (resp.status() == 0) return SkillResult.err(name(), "Cannot connect to " + url);
        var findings = new ArrayList<String>();
        // Security headers
        var SEC = List.of("strict-transport-security","content-security-policy","x-frame-options","x-content-type-options");
        var missingHdrs = SEC.stream().filter(h -> !resp.headers().containsKey(h)).collect(Collectors.toList());
        if (!missingHdrs.isEmpty()) findings.add("[MEDIUM] Missing security headers: " + String.join(", ", missingHdrs));
        // Info disclosure
        if (!resp.headers().getOrDefault("server","").isBlank()) findings.add("[LOW] Server header: " + resp.headers().get("server"));
        if (!resp.headers().getOrDefault("x-powered-by","").isBlank()) findings.add("[LOW] X-Powered-By: " + resp.headers().get("x-powered-by"));
        // SQLi probe
        var sqliResp = Http.get(url + "?id=" + URLEncoder.encode("' OR '1'='1", java.nio.charset.StandardCharsets.UTF_8), auth);
        if (sqliResp.body().toLowerCase().matches(".*?(sql syntax|mysql_fetch|ora-|sqlstate).*")) findings.add("[CRITICAL] SQLi: error returned for injection payload");
        // XSS probe
        String xssPayload = URLEncoder.encode("<script>alert(1)</script>", java.nio.charset.StandardCharsets.UTF_8);
        var xssResp = Http.get(url + "?q=" + xssPayload, auth);
        if (xssResp.body().contains("<script>alert(1)</script>")) findings.add("[HIGH] XSS: payload reflected in response");
        // Sensitive paths
        for (var p : List.of("/.env","/.git/HEAD","/phpinfo.php","/admin","/api/v1/users","/actuator/env")) {
            var pr = Http.get(url + p, auth);
            if (pr.status() == 200) findings.add("[" + (p.contains(".env")||p.contains("git")?"CRITICAL":"MEDIUM") + "] HTTP 200 at " + p);
        }
        String risk = findings.stream().anyMatch(f->f.startsWith("[CRITICAL]")) ? "critical" :
                      findings.stream().anyMatch(f->f.startsWith("[HIGH]"))     ? "high"     :
                      findings.isEmpty() ? "low" : "medium";
        var sb = new StringBuilder("**Web App Scanner** `" + url + "`\n\n");
        sb.append("  Baseline    : HTTP ").append(resp.status()).append("\n");
        sb.append("  Risk Level  : [").append(risk.toUpperCase()).append("]\n");
        sb.append("  Findings    : ").append(findings.size()).append("\n\n");
        if (findings.isEmpty()) sb.append("  ✓ No critical vulnerabilities detected\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f -> sb.append("    ").append(f).append("\n")); }
        return SkillResult.ok(name(), sb.toString(), "web_app_scan", url.split("/")[2]);
    }
}

record ApiSecurityAuditSkill() implements Skill {
    public String name()        { return "api_security_audit"; }
    public String description() { return "API security: auth check, rate limiting, CORS, endpoint discovery"; }
    public String usage()       { return "api_security_audit <base_url> [bearer_token]"; }
    public List<String> triggerPatterns() { return List.of("api security","api audit","api scan","rest api"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts = args.trim().split("\\s+",2);
        if (parts[0].isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String base = parts[0].startsWith("http") ? parts[0] : "https://"+parts[0];
        Map<String,String> auth = parts.length>1 ? Map.of("Authorization","Bearer "+parts[1]) : Map.of();
        var resp = Http.get(base, auth);
        if (resp.status()==0) return SkillResult.err(name(),"Cannot connect to "+base);
        var findings = new ArrayList<String>();
        // Auth check
        if (!auth.isEmpty()) {
            var noAuth = Http.get(base, Map.of());
            if (noAuth.status()==200) findings.add("[CRITICAL] Accessible without authentication");
        }
        // CORS
        String cors = resp.headers().getOrDefault("access-control-allow-origin","");
        if ("*".equals(cors)) findings.add("[HIGH] CORS: Access-Control-Allow-Origin: * (any origin allowed)");
        // Rate limiting
        boolean rl = resp.headers().keySet().stream().anyMatch(k -> k.contains("ratelimit")||k.contains("rate-limit")||k.contains("retry-after"));
        if (!rl) findings.add("[MEDIUM] No rate-limiting headers detected");
        // Sensitive endpoints
        var exec = Executors.newFixedThreadPool(10);
        var paths = List.of("/users","/admin","/swagger.json","/openapi.json","/.well-known/openid-configuration","/actuator","/actuator/env","/graphql","/api/v1/users","/health","/metrics");
        var futs  = paths.stream().map(p -> exec.submit(() -> { var r=Http.get(base+p,auth); return r.status()==200||r.status()==201?p:null; })).collect(Collectors.toList());
        exec.shutdown();
        futs.forEach(f -> { try { var r=f.get(5,TimeUnit.SECONDS); if(r!=null) findings.add("["+(r.contains("actuator")||r.contains("admin")?"CRITICAL":"MEDIUM")+"] HTTP 200 at "+r); } catch(Exception ignored){} });
        // Info disclosure
        if (!resp.headers().getOrDefault("server","").isBlank()) findings.add("[LOW] Server: "+resp.headers().get("server"));
        String risk = findings.stream().anyMatch(f->f.contains("CRITICAL"))?"critical":findings.stream().anyMatch(f->f.contains("HIGH"))?"high":findings.isEmpty()?"low":"medium";
        var sb = new StringBuilder("**API Security Audit** `"+base+"`\n\n");
        sb.append("  Baseline   : HTTP ").append(resp.status()).append("\n");
        sb.append("  Risk Level : [").append(risk.toUpperCase()).append("]\n");
        sb.append("  Issues     : ").append(findings.size()).append("\n\n");
        if (findings.isEmpty()) sb.append("  ✓ No critical API issues\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f->sb.append("    ").append(f).append("\n")); }
        return SkillResult.ok(name(), sb.toString(), "api_security", base.split("/")[2]);
    }
}

record FirewallAuditorSkill() implements Skill {
    public String name()        { return "firewall_auditor"; }
    public String description() { return "Firewall rules audit: parse iptables/nftables, detect over-permissive policies"; }
    public String usage()       { return "firewall_auditor <paste iptables rules>"; }
    public List<String> triggerPatterns() { return List.of("firewall audit","firewall rules","iptables","nftables"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String rules = args.strip();
        // Try live grab if single word
        if (!rules.contains("\n") && !rules.contains(" ")) {
            if (rules.equals("localhost") || rules.equals("127.0.0.1")) {
                try {
                    var r = Runtime.getRuntime().exec(new String[]{"iptables","-S"});
                    String out = new String(r.getInputStream().readAllBytes()).strip();
                    if (!out.isEmpty()) rules = out;
                } catch (Exception e) { return SkillResult.err(name(), "Cannot grab live rules: install iptables or paste rules directly"); }
            } else return SkillResult.err(name(), "Paste iptables -S output directly, or use 'localhost' for local system");
        }
        var findings = new ArrayList<String[]>();
        var DANGER = List.of(
            new String[]{"-s 0.0.0.0/0.*--dport 22",  "critical","SSH open to 0.0.0.0/0"},
            new String[]{"-s 0.0.0.0/0.*--dport 3389","critical","RDP open to 0.0.0.0/0"},
            new String[]{"-s 0.0.0.0/0.*--dport 21",  "high",    "FTP open to 0.0.0.0/0"},
            new String[]{"-s 0.0.0.0/0.*--dport 23",  "critical","Telnet open to 0.0.0.0/0"},
            new String[]{"policy ACCEPT",              "medium",  "Default ACCEPT policy"},
            new String[]{"-A FORWARD -j ACCEPT",       "high",    "Unrestricted forwarding"},
            new String[]{"--dport 445.*-j ACCEPT",     "high",    "SMB/445 exposed"}
        );
        for (var d : DANGER) {
            var pat = Pattern.compile(d[0], Pattern.CASE_INSENSITIVE);
            if (rules.lines().anyMatch(l -> pat.matcher(l).find())) findings.add(d);
        }
        long accepts = rules.lines().filter(l -> l.contains("-j ACCEPT")).count();
        long drops   = rules.lines().filter(l -> l.contains("-j DROP")||l.contains("-j REJECT")).count();
        boolean egress = rules.lines().anyMatch(l -> l.contains("OUTPUT") && (l.contains("DROP")||l.contains("REJECT")));
        if (!egress) findings.add(new String[]{"","medium","No egress DROP rules — unrestricted outbound"});
        String risk = findings.stream().anyMatch(f->"critical".equals(f[1]))?"critical":findings.stream().anyMatch(f->"high".equals(f[1]))?"high":findings.isEmpty()?"low":"medium";
        var sb = new StringBuilder("**Firewall Rules Audit**\n\n");
        sb.append("  Rules parsed: ").append(rules.lines().count()).append("\n");
        sb.append("  ACCEPT rules: ").append(accepts).append("\n");
        sb.append("  DROP/REJECT : ").append(drops).append("\n\n");
        sb.append("  **Risk Level: [").append(risk.toUpperCase()).append("]**\n\n");
        if (findings.isEmpty()) sb.append("  ✓ No obvious over-permissive rules detected\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f->sb.append("    [").append(f[1].toUpperCase()).append("] ").append(f[2]).append("\n")); }
        var tags = new ArrayList<>(List.of("firewall_audit"));
        if (List.of("critical","high").contains(risk)) tags.add("overpermissive_firewall");
        return SkillResult.ok(name(), sb.toString(), tags.toArray(String[]::new));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLOUD / CONTAINER / AUTH SKILLS
// ═════════════════════════════════════════════════════════════════════════════

record CloudPostureSkill() implements Skill {
    public String name()        { return "cloud_posture"; }
    public String description() { return "Cloud security posture: AWS/GCP/Azure IAM, public buckets, security groups"; }
    public String usage()       { return "cloud_posture <account_id|project|sub> [aws|gcp|azure]"; }
    public List<String> triggerPatterns() { return List.of("cloud posture","cloud security","aws security","s3 bucket","iam review"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts    = args.trim().split("\\s+");
        String target= parts[0]; String provider= parts.length>1?parts[1].toLowerCase():"aws";
        var sb       = new StringBuilder("**Cloud Security Posture** `"+target+"` ("+provider.toUpperCase()+")\n\n");
        var findings = new ArrayList<String>();
        // Try AWS CLI
        if ("aws".equals(provider)) {
            try {
                var r = Runtime.getRuntime().exec(new String[]{"aws","s3api","list-buckets","--query","Buckets[].Name","--output","json"});
                r.waitFor(20, TimeUnit.SECONDS);
                String out = new String(r.getInputStream().readAllBytes()).strip();
                if (r.exitValue()==0 && !out.isBlank() && !out.equals("null")) {
                    // Extract bucket names
                    var m = Pattern.compile("\"([^\"]+)\"").matcher(out);
                    while (m.find()) {
                        String bucket = m.group(1);
                        var pubResp = Http.get("https://"+bucket+".s3.amazonaws.com/");
                        if (pubResp.status()==200) findings.add("[CRITICAL] Public S3 bucket: "+bucket);
                        else if (pubResp.status()==403) sb.append("  Bucket "+bucket+": private (403)\n");
                    }
                }
            } catch (Exception e) {
                // No CLI — probe common bucket patterns
                sb.append("  AWS CLI not available — probing common bucket names\n");
                for (String suffix : new String[]{"","-public","-data","-backup","-dev"}) {
                    var resp = Http.get("https://"+target+suffix+".s3.amazonaws.com/");
                    if (resp.status()==200) findings.add("[CRITICAL] Public S3 bucket: "+target+suffix);
                    else if (resp.status()==403) sb.append("  "+target+suffix+": exists but private (403)\n");
                }
            }
        } else {
            sb.append("  Install ").append(provider).append(" CLI and configure credentials for full check\n");
            findings.add("[INFO] Manual "+provider.toUpperCase()+" CLI checks required");
        }
        String risk = findings.stream().anyMatch(f->f.contains("CRITICAL"))?"critical":findings.isEmpty()?"info":"medium";
        sb.append("\n  **Risk Level: [").append(risk.toUpperCase()).append("]**\n\n");
        if (findings.isEmpty()) sb.append("  ✓ No public exposures detected\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f->sb.append("    ").append(f).append("\n")); }
        return SkillResult.ok(name(), sb.toString(), "cloud_posture", provider, target.substring(0,Math.min(40,target.length())));
    }
}

record ContainerScannerSkill() implements Skill {
    public String name()        { return "container_scanner"; }
    public String description() { return "Container security: Docker inspect, Dockerfile audit, secret scan"; }
    public String usage()       { return "container_scanner <image:tag OR Dockerfile_path>"; }
    public List<String> triggerPatterns() { return List.of("container scan","docker scan","image scan","dockerfile"); }
    public SkillResult run(String args, MemoryManager mm) {
        String target = args.trim();
        if (target.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        var sb = new StringBuilder("**Container Security Scan** `"+target+"`\n\n");
        var findings = new ArrayList<String[]>();
        // Check if Dockerfile
        Path df = Path.of(target);
        if (df.toFile().exists()) {
            try {
                String content = Files.readString(df);
                sb.append("  Source: Dockerfile\n  Lines : ").append(content.lines().count()).append("\n\n");
                if (Pattern.compile("(?i)^FROM.*:latest",Pattern.MULTILINE).matcher(content).find()) findings.add(new String[]{"medium","Using :latest tag — unpinned"});
                if (Pattern.compile("(?i)^USER\\s+root",Pattern.MULTILINE).matcher(content).find()) findings.add(new String[]{"critical","Running as root user"});
                if (Pattern.compile("(?i)chmod\\s+777").matcher(content).find()) findings.add(new String[]{"high","chmod 777 — world-writable"});
                if (Pattern.compile("(?i)--privileged").matcher(content).find()) findings.add(new String[]{"critical","--privileged flag"});
                if (Pattern.compile("(?i)(password|api_key|secret)\\s*=\\s*[^\\s]{4,}",Pattern.MULTILINE).matcher(content).find()) findings.add(new String[]{"critical","Potential secret in Dockerfile"});
                if (Pattern.compile("(?i)^ADD\\s+http",Pattern.MULTILINE).matcher(content).find()) findings.add(new String[]{"high","ADD from remote URL (no checksum)"});
            } catch (Exception e) { return SkillResult.err(name(), "Cannot read Dockerfile: " + e.getMessage()); }
        } else {
            // Try docker inspect
            try {
                var r = Runtime.getRuntime().exec(new String[]{"docker","inspect",target});
                r.waitFor(15, TimeUnit.SECONDS);
                String out = new String(r.getInputStream().readAllBytes()).strip();
                if (r.exitValue()==0 && !out.isBlank()) {
                    if (out.contains("\"User\": \"\"") || out.contains("\"User\":\"\"")) findings.add(new String[]{"critical","Container runs as root"});
                    if (out.contains("\"Privileged\": true")) findings.add(new String[]{"critical","--privileged mode enabled"});
                    if (Pattern.compile("(?i)(PASSWORD|API_KEY|SECRET)\\s*=").matcher(out).find()) findings.add(new String[]{"critical","Secret in environment variables"});
                } else {
                    sb.append("  Docker not available — NVD CVE lookup for '").append(target.split(":")[0]).append("'\n");
                    String imgName = target.split(":")[0].replaceAll(".*/","");
                    var resp = Http.get("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="+imgName+"&resultsPerPage=3");
                    if (resp.status()==200) {
                        var m = Pattern.compile("\"id\"\\s*:\\s*\"(CVE-[^\"]+)\"").matcher(resp.body());
                        int cnt=0; while (m.find()&&cnt++<3) findings.add(new String[]{"medium","NVD: "+m.group(1)+" for '"+imgName+"'"});
                    }
                }
            } catch (Exception e) { findings.add(new String[]{"info","Docker CLI not available: "+e.getMessage().substring(0,Math.min(60,e.getMessage().length()))}); }
        }
        String risk = findings.stream().anyMatch(f->"critical".equals(f[0]))?"critical":findings.stream().anyMatch(f->"high".equals(f[0]))?"high":findings.isEmpty()?"low":"medium";
        sb.append("  **Risk Level: [").append(risk.toUpperCase()).append("]**\n\n");
        if (findings.isEmpty()) sb.append("  ✓ No critical container issues\n");
        else { sb.append("  **Findings:**\n"); findings.forEach(f->sb.append("    [").append(f[0].toUpperCase()).append("] ").append(f[1]).append("\n")); }
        return SkillResult.ok(name(), sb.toString(), "container_scan", target.substring(0,Math.min(40,target.length())));
    }
}

record PasswordAuditSkill() implements Skill {
    public String name()        { return "password_audit"; }
    public String description() { return "Password security: policy check, lockout probe, hash detection"; }
    public String usage()       { return "password_audit <target_url_or_system> [policy_notes]"; }
    public List<String> triggerPatterns() { return List.of("password audit","password security","brute force risk","auth policy"); }
    public SkillResult run(String args, MemoryManager mm) {
        var parts = args.trim().split("\\s+", 2);
        if (parts[0].isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        String target = parts[0]; String policy = parts.length>1?parts[1]:"";
        boolean isUrl = target.startsWith("http");
        var sb = new StringBuilder("**Password Security Audit** `"+target+"`\n\n");
        var issues = new ArrayList<String>();
        // Hash detection
        if (target.matches("[\\$a-fA-F0-9]{32,}")) {
            String algo = target.startsWith("$2") ? "bcrypt (strong)" : target.startsWith("$1") ? "MD5-crypt [WEAK]" : target.matches("[0-9a-fA-F]{32}") ? "MD5-plain [CRITICAL]" : target.matches("[0-9a-fA-F]{64}") ? "SHA-256 [MEDIUM]" : "unknown";
            sb.append("  Hash Algorithm: ").append(algo).append("\n");
            if (algo.contains("WEAK") || algo.contains("CRITICAL")) issues.add("[CRITICAL] Weak hash: " + algo);
        }
        // Transport check
        if (isUrl) {
            sb.append("  Transport : ").append(target.startsWith("https")?"✓ HTTPS":"[CRITICAL] HTTP — plaintext credentials").append("\n");
            if (!target.startsWith("https")) issues.add("[CRITICAL] Credentials sent in plaintext over HTTP");
            // Lockout probe
            String[] WEAK = {"password","123456","admin","root","test","letmein"};
            boolean lockout = false;
            for (int i = 0; i < WEAK.length && !lockout; i++) {
                try {
                    String body = URLEncoder.encode("username=admin&password="+WEAK[i], java.nio.charset.StandardCharsets.UTF_8);
                    var conn = (HttpURLConnection) new URL(target).openConnection();
                    conn.setRequestMethod("POST"); conn.setDoOutput(true); conn.setConnectTimeout(5000); conn.setReadTimeout(5000);
                    conn.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
                    conn.getOutputStream().write(body.getBytes());
                    int code = conn.getResponseCode();
                    if (code == 429) { lockout = true; sb.append("  Lockout   : ✓ Rate-limited after ").append(i+1).append(" attempt(s)\n"); }
                    conn.disconnect();
                } catch (Exception ignored) {}
            }
            if (!lockout) { sb.append("  Lockout   : [CRITICAL] No lockout detected — brute-force risk\n"); issues.add("[CRITICAL] No account lockout"); }
        }
        // Policy assessment via AI if provided
        if (!policy.isBlank()) {
            try {
                String analysis = DS.call("You are a password policy auditor. Reply with ONE sentence risk assessment.",
                    List.of(Map.of("role","user","content","Policy: "+policy)), 128, 0.2);
                sb.append("  Policy AI : ").append(analysis.substring(0,Math.min(200,analysis.length()))).append("\n");
            } catch (Exception e) { sb.append("  Policy    : ").append(policy).append("\n"); }
        }
        String risk = issues.stream().anyMatch(i->i.contains("CRITICAL"))?"critical":issues.isEmpty()?"low":"medium";
        sb.append("\n  **Risk Level: [").append(risk.toUpperCase()).append("]**\n");
        if (!issues.isEmpty()) { sb.append("\n  **Issues:**\n"); issues.forEach(i->sb.append("    ").append(i).append("\n")); }
        return SkillResult.ok(name(), sb.toString(), "password_audit", target.substring(0,Math.min(40,target.length())));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// UTILITY SKILLS
// ═════════════════════════════════════════════════════════════════════════════

record SummarizerSkill() implements Skill {
    public String name()        { return "summarizer"; }
    public String description() { return "Summarize text using DeepSeek"; }
    public String usage()       { return "summarizer <text>"; }
    public List<String> triggerPatterns() { return List.of("summarize","tldr","condense"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        try {
            String s = DS.call("Return only a concise summary, no preamble.",
                List.of(Map.of("role","user","content","Summarize:\n"+args.substring(0,Math.min(6000,args.length())))), 512, 0.3);
            return SkillResult.ok(name(), "**Summary:**\n" + s, "summary");
        } catch (Exception e) { return SkillResult.err(name(), e.getMessage()); }
    }
}

record MemoryWriterSkill() implements Skill {
    public String name()        { return "memory_writer"; }
    public String description() { return "Write a fact to long-term memory"; }
    public String usage()       { return "memory_writer <text>"; }
    public List<String> triggerPatterns() { return List.of("remember this","save to memory","note this"); }
    public SkillResult run(String args, MemoryManager mm) {
        if (args.isBlank()) return SkillResult.err(name(), "Usage: " + usage());
        var e = mm.archive.store(args.strip(), "skill_memory_writer", List.of("fact"));
        return SkillResult.ok(name(), "✓ Stored → `" + e.id() + "`");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SkillRegistry
// ─────────────────────────────────────────────────────────────────────────────

final class SkillRegistry {
    private static final Logger LOG = Logger.getLogger(SkillRegistry.class.getName());
    private final List<Skill> all;

    SkillRegistry() {
        all = List.of(
            // NETWORK
            new PortScannerSkill(), new DnsLookupSkill(), new WhoisLookupSkill(),
            new SslCertInspectorSkill(), new HttpHeaderAnalyzerSkill(),
            new NetworkReconSkill(), new DnsSecuritySkill(),
            // THREAT
            new CveLookupSkill(), new IpReputationSkill(),
            new HashLookupSkill(), new IocExtractorSkill(),
            // ANALYSIS
            new LogAnalyzerSkill(), new VulnerabilityScorerSkill(),
            new VulnerabilityAssessmentSkill(), new WebAppScannerSkill(),
            new ApiSecurityAuditSkill(), new FirewallAuditorSkill(),
            // CLOUD / CONTAINER / AUTH
            new CloudPostureSkill(), new ContainerScannerSkill(), new PasswordAuditSkill(),
            // UTILITY
            new SummarizerSkill(), new MemoryWriterSkill()
        );
        LOG.info("SkillRegistry: " + all.size() + " skills loaded.");
    }

    Optional<Skill> get(String name) { return all.stream().filter(s -> s.name().equals(name)).findFirst(); }
    List<Skill> all() { return all; }
    Optional<Skill> detect(String text) {
        String low = text.toLowerCase();
        return all.stream().filter(s -> s.triggerPatterns().stream().anyMatch(low::contains)).findFirst();
    }
    String helpText() {
        var sections = new LinkedHashMap<String,List<String>>();
        sections.put("NETWORK",   List.of("port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector","http_header_analyzer","network_recon","dns_security"));
        sections.put("THREAT",    List.of("cve_lookup","ip_reputation","hash_lookup","ioc_extractor"));
        sections.put("ANALYSIS",  List.of("log_analyzer","vulnerability_scorer","vulnerability_assessment","web_app_scanner","api_security_audit","firewall_auditor"));
        sections.put("CLOUD/CTR", List.of("cloud_posture","container_scanner"));
        sections.put("AUTH",      List.of("password_audit"));
        sections.put("UTILITY",   List.of("summarizer","memory_writer"));
        var sb = new StringBuilder("**SecOps Skills v1.0.2 — 22 skills:**\n\n");
        sections.forEach((sec, names) -> {
            sb.append("  ── ").append(sec).append(" ──\n");
            names.forEach(n -> get(n).ifPresent(s -> sb.append("  `").append(s.name()).append("` — ").append(s.description()).append("\n    ").append(s.usage()).append("\n\n")));
        });
        return sb.toString();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReAct Engine
// ─────────────────────────────────────────────────────────────────────────────

final class ReactEngine {
    private static final Logger LOG = Logger.getLogger(ReactEngine.class.getName());
    private static final Pattern RE_THOUGHT = Pattern.compile("Thought:\\s*([\\s\\S]+?)(?=\\nAction:|\\nFinal Answer:|$)");
    private static final Pattern RE_ACTION  = Pattern.compile("Action:\\s*(\\w+)\\s*(.*?)(?:\\n|$)");
    private static final Pattern RE_FINAL   = Pattern.compile("Final Answer:\\s*([\\s\\S]+)");
    static final int MAX_ITER = 10, MAX_ERRS = 3;

    private final MemoryManager mm;
    private final SkillRegistry skills;

    ReactEngine(MemoryManager mm, SkillRegistry skills) { this.mm=mm; this.skills=skills; }

    private String buildSystem() {
        String skillList = skills.all().stream().map(s -> "  "+s.name()+": "+s.description()).collect(Collectors.joining("\n"));
        String base = mm.contextForQuery(mm.react().getGoal(), 3, 0.05);
        return base + "\n\n---\n\nYou are in ReAct mode.\nEach response: Thought: <reasoning>\\nAction: <skill> <args>\nOR: Thought: <reasoning>\\nFinal Answer: <answer>\nSkills:\n" + skillList + "\nNever fabricate Observations. Check layer 2.5 trace.";
    }

    private Map<String,String> parse(String text) {
        var out = new HashMap<String,String>();
        var mt = RE_THOUGHT.matcher(text); if (mt.find()) out.put("thought", mt.group(1).strip());
        var ma = RE_ACTION.matcher(text);  if (ma.find()) { out.put("action", ma.group(1).strip()); out.put("args", ma.group(2).strip()); }
        var mf = RE_FINAL.matcher(text);   if (mf.find()) out.put("final", mf.group(1).strip());
        return out;
    }

    private String[] execSkill(String name, String args) {
        return skills.get(name).map(skill -> {
            try {
                SkillResult r = skill.run(args, mm);
                if (r.storeToArchive() && r.success())
                    mm.archive.store("["+r.skill()+"] "+r.output().substring(0,Math.min(500,r.output().length())),
                        "skill_"+r.skill(), r.archiveTags());
                return new String[]{r.output(), String.valueOf(!r.success())};
            } catch (Exception e) { return new String[]{"Skill error: "+e.getMessage(),"true"}; }
        }).orElse(new String[]{"Unknown skill '"+name+"'. Available: "+skills.all().stream().map(Skill::name).collect(Collectors.joining(", ")),"true"});
    }

    String run(String goal) {
        mm.enableReact(goal);
        var rm = mm.react(); int errs = 0;
        System.err.println("\n🔄 ReAct: " + goal + "\n" + "─".repeat(60));
        for (int i = 1; i <= MAX_ITER; i++) {
            long t0 = System.currentTimeMillis(); String raw;
            try { raw = DS.call(buildSystem(), mm.working.buildMessages(), 4096, 0.3); }
            catch (Exception e) { rm.record(TraceType.OBSERVATION,"LLM error: "+e.getMessage(),"",true,0); errs++; if(errs>=MAX_ERRS)break; continue; }
            int lat = (int)(System.currentTimeMillis()-t0);
            var p = parse(raw);
            String thought = p.getOrDefault("thought", raw.substring(0,Math.min(200,raw.length())));
            rm.record(TraceType.THOUGHT, thought, "", false, lat);
            System.err.println("  💭 ["+i+"] "+thought.substring(0,Math.min(100,thought.length())));
            if (p.containsKey("final")) {
                String ans = p.get("final");
                rm.record(TraceType.FINAL, ans);
                mm.addAssistantMessage(ans);
                mm.finishReact(ans);
                System.err.println("  ✅ Final: "+ans.substring(0,Math.min(160,ans.length()))+"\n"+"─".repeat(60));
                return ans;
            }
            String act = p.getOrDefault("action",""); String args = p.getOrDefault("args","");
            if (act.isBlank()) {
                rm.record(TraceType.OBSERVATION,"No Action.","",true,0);
                mm.working.addMessage("user","No Action found. Respond: Thought: ... then Action: <skill> <args>"); errs++;
            } else {
                rm.record(TraceType.ACTION,act+" "+args,act,false,0);
                System.err.println("  ⚡ ["+i+"] Action: "+act+" "+args.substring(0,Math.min(70,args.length())));
                long t1=System.currentTimeMillis(); var res=execSkill(act,args);
                rm.record(TraceType.OBSERVATION,res[0],"",Boolean.parseBoolean(res[1]),(int)(System.currentTimeMillis()-t1));
                System.err.println("  👁 ["+i+"] "+res[0].substring(0,Math.min(100,res[0].length())));
                if(Boolean.parseBoolean(res[1]))errs++;
                mm.working.addMessage("user","Observation: "+res[0]);
                mm.addAssistantMessage(raw);
            }
            if(errs>=MAX_ERRS){System.err.println("  ⚠ Max errors reached.");break;}
        }
        String fallback="Loop ended. Last: "+rm.lastObservation().substring(0,Math.min(200,rm.lastObservation().length()));
        mm.finishReact(fallback); return fallback;
    }

    String[] step(String goal) {
        if (!mm.react().isEnabled()) mm.enableReact(goal);
        String raw; try { raw=DS.call(buildSystem(),mm.working.buildMessages(),4096,0.3); } catch(Exception e){return new String[]{"⚠ LLM error: "+e.getMessage(),"false"};}
        var p=parse(raw); String thought=p.getOrDefault("thought",raw.substring(0,Math.min(200,raw.length())));
        mm.react().record(TraceType.THOUGHT,thought,"",false,0);
        if(p.containsKey("final")){mm.react().record(TraceType.FINAL,p.get("final"));mm.addAssistantMessage(p.get("final"));mm.finishReact(p.get("final"));return new String[]{"✅ **Final Answer:**\n"+p.get("final"),"true"};}
        String act=p.getOrDefault("action",""),args=p.getOrDefault("args","");
        if(act.isBlank()){mm.react().record(TraceType.OBSERVATION,"No Action.","",true,0);return new String[]{"💭 **Thought:** "+thought+"\n\n⚠ No Action.","false"};}
        mm.react().record(TraceType.ACTION,act+" "+args,act,false,0);
        var res=execSkill(act,args); mm.react().record(TraceType.OBSERVATION,res[0],"",Boolean.parseBoolean(res[1]),0);
        mm.working.addMessage("user","Observation: "+res[0]); mm.addAssistantMessage(raw);
        return new String[]{"💭 **Thought:** "+thought+"\n\n⚡ **Action:** `"+act+"` "+args.substring(0,Math.min(80,args.length()))+"\n\n👁 **Observation:** "+res[0].substring(0,Math.min(300,res[0].length())),"false"};
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent
// ─────────────────────────────────────────────────────────────────────────────

public class Agent {
    private static final Logger LOG = Logger.getLogger(Agent.class.getName());
    static final String BANNER = """

        ╔══════════════════════════════════════════════════════════════════╗
        ║     OMNIKON SEC·OPS  —  AI Agent  v1.0.2  (Java)               ║
        ║  LLM    : DeepSeek deepseek-chat                               ║
        ║  Skills : 22 real SecOps skills — UI-aligned, no mocks         ║
        ║────────────────────────────────────────────────────────────────║
        ║  /skills  /skill <name> <args>  /react <goal>  /react-step     ║
        ║  /react-status  /react-finish  /task  /step  /finish           ║
        ║  /status  /archive  /recall  /quit                             ║
        ╚══════════════════════════════════════════════════════════════════╝
        """;

    private final MemoryManager mm;
    private final SkillRegistry skills;
    private final ReactEngine   reactEngine;

    Agent(String archivePath) {
        this.mm = new MemoryManager(Path.of(archivePath));
        this.skills = new SkillRegistry();
        this.reactEngine = new ReactEngine(mm, skills);
        configurePersona(); configureRules(); seedKnowledge();
    }

    private void configurePersona() {
        mm.character().name = "OMNIKON SEC·OPS"; mm.character().tone = "precise and analytical";
        mm.character().expertise = new ArrayList<>(List.of("cybersecurity","network security","CVSS","OWASP","cloud security","ReAct"));
        mm.character().personality = "Evidence-first. Chains skills for deep investigation. Uses ReAct for complex multi-step analysis.";
        mm.character().responseFormat = "Markdown";
        mm.character().constraints = new ArrayList<>(List.of(
            "Never reveal API keys or credentials.",
            "[CRITICAL] prefix for CVSS≥7.0 or confirmed attacks.",
            "In ReAct: Thought → Action → Observation always."
        ));
    }

    private void configureRules() {
        mm.addSystemRule("Respond only in English.");
        mm.addSystemRule("Skills (" + skills.all().size() + "): " + skills.all().stream().map(Skill::name).collect(Collectors.joining(", ")));
        mm.addSystemRule("Skill chaining: dns_lookup → port_scanner → ssl_cert_inspector → http_header_analyzer | vulnerability_assessment → cve_lookup → vulnerability_scorer");
    }

    private void seedKnowledge() {
        if (mm.archive.size() > 0) return;
        mm.archive.store("CVE-2024-1234: SQL injection AuthService v2.1 CVSS 9.8. Patch: v2.2+.", "knowledge_base", List.of("cve"));
        mm.archive.store("Brute-force: 5+ failures single IP <10 min → rate-limit + SOC alert.", "playbook", List.of("brute-force"));
        mm.archive.store("OWASP Top 10 2021: A01 Broken Access, A02 Crypto, A03 Injection.", "knowledge_base", List.of("owasp"));
        mm.archive.store("Security headers required: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.", "playbook", List.of("headers"));
    }

    private String execSkill(String args) {
        var parts = args.strip().split("\\s+", 2);
        String name = parts[0]; String sargs = parts.length > 1 ? parts[1] : "";
        return skills.get(name).map(skill -> {
            SkillResult r = skill.run(sargs, mm);
            if (r.storeToArchive() && r.success())
                mm.archive.store("["+r.skill()+"] "+r.output().substring(0,Math.min(500,r.output().length())), "skill_"+r.skill(), r.archiveTags());
            return r.output();
        }).orElse("⚠ Unknown skill '" + name + "'. Try /skills");
    }

    String chat(String input) {
        String s = input.strip();
        if (s.isBlank()) return "";
        if (s.startsWith("/")) {
            var parts = s.substring(1).split("\\s+", 2);
            String cmd = parts[0].toLowerCase(); String args = parts.length > 1 ? parts[1] : "";
            return switch (cmd) {
                case "quit","exit","q" -> { System.exit(0); yield ""; }
                case "skills"       -> skills.helpText();
                case "skill"        -> execSkill(args);
                case "react"        -> args.isBlank() ? "Usage: /react <goal>" : reactEngine.run(args.strip());
                case "react-step"   -> {
                    String goal = args.isBlank() ? (mm.react().getGoal().isBlank() ? "Investigate" : mm.react().getGoal()) : args;
                    var res = reactEngine.step(goal);
                    yield res[0] + (Boolean.parseBoolean(res[1]) ? "\n\n_(done — /react-finish to archive)_" : "\n\n_(run /react-step again)_");
                }
                case "react-status" -> {
                    var rm = mm.react();
                    if (!rm.isEnabled()) yield "ℹ ReAct not active.";
                    var d = rm.snapshotMap();
                    var sb = new StringBuilder("```\nGoal: ").append(d.get("goal")).append("  Iters: ").append(d.get("totalIterations")).append("  Errors: ").append(d.get("totalErrors")).append("  Elapsed: ").append(d.get("elapsedS")).append("s\n```\n**Last 6:**\n");
                    rm.getTraces().stream().skip(Math.max(0,rm.getTraces().size()-6)).forEach(t -> sb.append("  [").append(t.traceType()).append("] ").append(t.content().substring(0,Math.min(80,t.content().length()))).append("\n"));
                    yield sb.toString();
                }
                case "react-finish" -> { var e = mm.finishReact(args); yield "✓ ReAct closed." + e.map(x -> " Archived → `" + x.id() + "`").orElse(""); }
                case "task"  -> {
                    var tparts = args.split("\\|"); String obj = tparts[0].strip();
                    if (obj.isBlank()) yield "Usage: /task <objective> [| step1 | ...]";
                    var steps = Arrays.stream(tparts).skip(1).map(String::strip).filter(p -> !p.isBlank()).collect(Collectors.toList());
                    mm.startTask(obj, steps); yield "✓ Task: **" + obj + "**";
                }
                case "step"  -> {
                    try { mm.completeStep(args.isBlank()?null:args); var st=mm.status(); yield "✓ Step "+st.currentStep+"/"+st.totalSteps+" | Next: "+(st.pending.isEmpty()?"none":String.join(", ",st.pending)); }
                    catch (Exception e) { yield "⚠ " + e.getMessage(); }
                }
                case "finish" -> {
                    try { var e=mm.finishTask(args.isBlank()?null:args); yield "✓ Archived → `"+e.id()+"`"; }
                    catch (Exception e) { yield "⚠ " + e.getMessage(); }
                }
                case "status" -> {
                    var snap = mm.snapshot();
                    String react = Boolean.TRUE.equals(snap.get("reactEnabled")) ? "ON — "+((Map<?,?>)snap.getOrDefault("reasoning",Map.of())).getOrDefault("goal","") : "OFF";
                    yield "```\nCharacter : "+snap.get("characterName")+"\nLLM       : "+DS.MODEL+"\nSkills    : "+skills.all().size()+"\nTask      : "+snap.get("taskObjective")+" ("+snap.get("taskProgressPct")+"%)\nArchive   : "+snap.get("archiveTotal")+" entries\nTokens≈   : "+snap.get("estimatedTokens")+"\nReAct     : "+react+"\n```";
                }
                case "archive" -> { if(args.isBlank()) yield "Usage: /archive <text>"; yield "✓ Stored → `"+mm.archive.store(args.strip(),"manual",List.of()).id()+"`"; }
                case "recall"  -> {
                    if (args.isBlank()) yield "Usage: /recall <query>";
                    var hits = mm.archive.retrieve(args.strip(), 5, 0.05);
                    if (hits.isEmpty()) yield "No memories found.";
                    var sb = new StringBuilder("**Recall:**\n");
                    for (int i=0;i<hits.size();i++) sb.append(i+1).append(". [").append(hits.get(i).source()).append("] ").append(hits.get(i).content().substring(0,Math.min(120,hits.get(i).content().length()))).append("…\n");
                    yield sb.toString();
                }
                default -> "Unknown command: /" + cmd;
            };
        }
        skills.detect(s).ifPresent(hint -> mm.addTaskContent("[Skill hint: " + hint.name() + " — try /skill " + hint.name() + " or /react]"));
        mm.addUserMessage(s);
        try {
            String reply = DS.call(mm.contextForQuery(s,3,0.05), mm.working.buildMessages(), 4096, 0.7);
            mm.addAssistantMessage(reply);
            return reply;
        } catch (Exception e) { return "⚠ LLM error: " + e.getMessage(); }
    }

    public static void main(String[] args) throws IOException {
        var handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        Logger.getLogger("").addHandler(handler);
        Logger.getLogger("").setLevel(Level.WARNING);

        String archivePath = Optional.ofNullable(System.getenv("ARCHIVE_PATH")).orElse("agent_memory.jsonl");
        System.out.println(BANNER);
        var agent = new Agent(archivePath);
        System.out.println("  Archive : " + archivePath + " (" + agent.mm.archive.size() + " entries)");
        System.out.println("  Skills  : " + agent.skills.all().size() + "\n");
        System.out.println("  Optional: ABUSEIPDB_API_KEY  VIRUSTOTAL_API_KEY\n");

        var reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("You > ");
        String line;
        while ((line = reader.readLine()) != null) {
            String t = line.strip();
            if (!t.isBlank()) {
                String reply = agent.chat(t);
                if (!reply.isBlank()) System.out.println("\nAgent >\n" + reply + "\n");
            }
            System.out.print("You > ");
        }
        System.out.println("\nGoodbye.");
    }
}
