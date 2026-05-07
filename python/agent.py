#!/usr/bin/env python3
"""
# =============================================================================
# agent.py
# =============================================================================
# Project  : OMNIKON SEC·OPS — AI Memory Agent
# Version  : v1.0.2
# Language : Python 3.11+
# License  : MIT
#
# Full ReAct AI agent with 21 production SecOps skills (no mocks).
# Skills aligned with cybersec-dashboard.jsx UI tool set.
#
# Skills (all real functionality):
#   NETWORK  : port_scanner, dns_lookup, whois_lookup, ssl_cert_inspector,
#              http_header_analyzer, network_recon, dns_security
#   THREAT   : cve_lookup, ip_reputation, hash_lookup, ioc_extractor
#   ANALYSIS : log_analyzer, vulnerability_scorer, vulnerability_assessment,
#              web_app_scanner, api_security_audit, firewall_auditor
#   CLOUD    : cloud_posture, container_scanner
#   AUTH     : password_audit
#   UTILITY  : summarizer, memory_writer
#
# Usage:
#   export DEEPSEEK_API_KEY=sk-...
#   export VIRUSTOTAL_API_KEY=<optional>
#   export SHODAN_API_KEY=<optional>
#   python agent.py [--archive PATH]
# =============================================================================
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from memory_manager import MemoryManager, TraceType

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Agent")

# ─────────────────────────────────────────────────────────────────────────────
# DeepSeek API
# ─────────────────────────────────────────────────────────────────────────────

DEEPSEEK_URL   = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"
MAX_TOKENS     = 4096


def _api_key() -> str:
    k = os.getenv("DEEPSEEK_API_KEY", "")
    if not k:
        raise RuntimeError("DEEPSEEK_API_KEY not set.\n  export DEEPSEEK_API_KEY=sk-...")
    return k


def call_deepseek(system: str, messages: list[dict], *,
                  max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> str:
    payload = json.dumps({
        "model": DEEPSEEK_MODEL, "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "system", "content": system}] + messages,
    }).encode()
    req = urllib.request.Request(
        DEEPSEEK_URL, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_api_key()}"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"DeepSeek {e.code}: {e.read().decode()!r}") from e


# ─────────────────────────────────────────────────────────────────────────────
# Skill base
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SkillResult:
    skill:            str
    success:          bool
    output:           str
    store_to_archive: bool      = False
    archive_tags:     list[str] = field(default_factory=list)


class Skill(ABC):
    trigger_patterns: list[str] = []
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def description(self) -> str: ...
    @property
    @abstractmethod
    def usage(self) -> str: ...
    @abstractmethod
    def run(self, args: str, mm: MemoryManager) -> SkillResult: ...


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK SKILLS
# ─────────────────────────────────────────────────────────────────────────────

class PortScannerSkill(Skill):
    """Real TCP connect scan against a target — no nmap dependency."""
    name             = "port_scanner"
    description      = "TCP connect scan on host:ports — e.g. 192.168.1.1 22,80,443"
    usage            = "port_scanner <host> <ports>  (ports: 22,80,443 or 1-1024)"
    trigger_patterns = ["port scan", "scan ports", "open ports", "port check"]
    TIMEOUT          = 1.5
    MAX_PORTS        = 500

    def _resolve(self, host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve {host}: {e}") from e

    def _parse_ports(self, spec: str) -> list[int]:
        ports: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), int(b) + 1))
            else:
                ports.append(int(part))
        if len(ports) > self.MAX_PORTS:
            raise ValueError(f"Too many ports (max {self.MAX_PORTS})")
        return ports

    def _scan_port(self, ip: str, port: int) -> tuple[int, bool, str]:
        try:
            with socket.create_connection((ip, port), timeout=self.TIMEOUT) as s:
                # Banner grab (best effort)
                s.settimeout(0.3)
                try:
                    banner = s.recv(256).decode(errors="replace").strip()[:80]
                except Exception:
                    banner = ""
                return port, True, banner
        except (ConnectionRefusedError, TimeoutError, OSError):
            return port, False, ""

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        host, port_spec = parts
        try:
            ip    = self._resolve(host)
            ports = self._parse_ports(port_spec)
        except ValueError as e:
            return SkillResult(self.name, False, f"⚠ {e}")

        open_ports: list[tuple[int, str]] = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(self._scan_port, ip, p): p for p in ports}
            for fut in as_completed(futs):
                port, is_open, banner = fut.result()
                if is_open:
                    open_ports.append((port, banner))

        open_ports.sort()
        if not open_ports:
            out = f"**Port Scan** {host} ({ip}) — no open ports found in {port_spec}"
            return SkillResult(self.name, True, out)

        lines = [f"**Port Scan** {host} ({ip}) — {len(open_ports)} open port(s)\n"]
        for port, banner in open_ports:
            svc = _well_known_service(port)
            b   = f" — `{banner}`" if banner else ""
            lines.append(f"  {port:5d}/tcp  OPEN  {svc}{b}")
        out = "\n".join(lines)
        return SkillResult(self.name, True, out, True,
                           ["port_scan", host, f"open_ports:{len(open_ports)}"])


def _well_known_service(port: int) -> str:
    SERVICES = {
        21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
        80:"http", 110:"pop3", 143:"imap", 389:"ldap", 443:"https",
        445:"smb", 3306:"mysql", 3389:"rdp", 5432:"postgres",
        6379:"redis", 8080:"http-alt", 8443:"https-alt",
        27017:"mongodb", 5900:"vnc", 11211:"memcached",
    }
    return SERVICES.get(port, "unknown")


class DnsLookupSkill(Skill):
    """Real DNS resolution using stdlib socket — A, AAAA, MX, NS, TXT via dig fallback."""
    name             = "dns_lookup"
    description      = "DNS resolution: A, AAAA, MX, TXT, NS, PTR, reverse lookup"
    usage            = "dns_lookup <hostname|ip> [type]  type=A|AAAA|MX|TXT|NS|PTR"
    trigger_patterns = ["dns lookup", "resolve hostname", "dns record", "nslookup"]

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split()
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        target   = parts[0]
        rec_type = parts[1].upper() if len(parts) > 1 else "A"
        lines    = [f"**DNS Lookup** `{target}` ({rec_type})\n"]

        try:
            if rec_type == "PTR" or _is_ip(target):
                # Reverse lookup
                hostname, aliases, _ = socket.gethostbyaddr(target)
                lines.append(f"  PTR  {hostname}")
                for a in aliases:
                    lines.append(f"  ALT  {a}")
            elif rec_type in ("A", "AAAA"):
                family = socket.AF_INET6 if rec_type == "AAAA" else socket.AF_INET
                infos  = socket.getaddrinfo(target, None, family)
                seen   = set()
                for info in infos:
                    ip = info[4][0]
                    if ip not in seen:
                        lines.append(f"  {rec_type:<5} {ip}")
                        seen.add(ip)
            else:
                # Fall back to system dig for MX/TXT/NS
                result = subprocess.run(
                    ["dig", "+short", rec_type, target],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0 or not result.stdout.strip():
                    lines.append(f"  No {rec_type} records found (or dig not available)")
                else:
                    for rec in result.stdout.strip().splitlines():
                        lines.append(f"  {rec_type:<5} {rec.strip()}")
        except (socket.herror, socket.gaierror) as e:
            return SkillResult(self.name, False, f"⚠ DNS error: {e}")
        except FileNotFoundError:
            lines.append("  ⚠ dig not installed; only A/AAAA/PTR available via stdlib")
        except subprocess.TimeoutExpired:
            return SkillResult(self.name, False, "⚠ DNS query timed out")

        out = "\n".join(lines)
        return SkillResult(self.name, True, out, True, ["dns", target])


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class WhoisLookupSkill(Skill):
    """Real WHOIS query via TCP port 43."""
    name             = "whois_lookup"
    description      = "WHOIS registration data for domain or IP (real WHOIS TCP query)"
    usage            = "whois_lookup <domain|ip>"
    trigger_patterns = ["whois", "domain registration", "ip owner", "registrar"]
    WHOIS_SERVERS    = {
        "default": "whois.iana.org",
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io":  "whois.nic.io",
        "uk":  "whois.nic.uk",
        "de":  "whois.denic.de",
    }

    def _whois_query(self, target: str, server: str) -> str:
        with socket.create_connection((server, 43), timeout=10) as s:
            s.sendall(f"{target}\r\n".encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode(errors="replace")

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        target = args.strip()
        if not target:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        # Pick WHOIS server
        if _is_ip(target):
            server = "whois.arin.net"
        else:
            tld    = target.rsplit(".", 1)[-1].lower()
            server = self.WHOIS_SERVERS.get(tld, self.WHOIS_SERVERS["default"])

        try:
            raw = self._whois_query(target, server)
            # If IANA returns a referral, follow it
            if server == "whois.iana.org":
                for line in raw.splitlines():
                    if line.strip().lower().startswith("whois:"):
                        refer = line.split(":", 1)[1].strip()
                        try:
                            raw = self._whois_query(target, refer)
                        except Exception:
                            pass
                        break

            # Extract key fields
            important = {}
            for line in raw.splitlines():
                for key in ("Registrar", "Registrant", "Creation Date", "Expiry Date",
                            "Updated Date", "Name Server", "Status", "NetRange",
                            "Organization", "OrgName", "Country"):
                    if line.strip().lower().startswith(key.lower() + ":"):
                        val = line.split(":", 1)[1].strip()
                        if key not in important:
                            important[key] = val

            lines = [f"**WHOIS** `{target}` (via {server})\n"]
            for k, v in important.items():
                lines.append(f"  {k:<20}: {v}")
            if not important:
                lines.append(raw[:800])

            out = "\n".join(lines)
            return SkillResult(self.name, True, out, True, ["whois", target])
        except (socket.timeout, ConnectionRefusedError) as e:
            return SkillResult(self.name, False, f"⚠ WHOIS connection failed: {e}")
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


class SslCertInspectorSkill(Skill):
    """Real SSL/TLS certificate inspection via stdlib ssl."""
    name             = "ssl_cert_inspector"
    description      = "Inspect TLS certificate: expiry, issuer, SANs, cipher, protocol"
    usage            = "ssl_cert_inspector <hostname> [port]  (default port 443)"
    trigger_patterns = ["ssl cert", "tls certificate", "certificate expiry", "https cert"]

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split()
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as s:
                    cert    = s.getpeercert()
                    cipher  = s.cipher()
                    version = s.version()

            # Parse expiry
            not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now        = datetime.now(timezone.utc)
            days_left  = (not_after - now).days
            expired    = days_left < 0
            expiry_tag = "[CRITICAL] EXPIRED" if expired else (
                         "[WARN] expires soon" if days_left < 30 else "valid")

            # Subject and issuer
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))

            # SANs
            sans = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]

            lines = [
                f"**SSL Certificate** `{host}:{port}`\n",
                f"  TLS Version : {version}",
                f"  Cipher      : {cipher[0] if cipher else 'unknown'}",
                f"  CN          : {subject.get('commonName', 'N/A')}",
                f"  Issuer      : {issuer.get('organizationName', 'N/A')}",
                f"  Valid From  : {not_before.strftime('%Y-%m-%d')}",
                f"  Expiry      : {not_after.strftime('%Y-%m-%d')} — {days_left}d left [{expiry_tag}]",
                f"  SANs        : {', '.join(sans[:10]) if sans else 'none'}",
            ]
            if len(sans) > 10:
                lines.append(f"  ... and {len(sans) - 10} more SANs")

            sev_tags = ["ssl_cert", host]
            if expired:
                sev_tags.append("expired_cert")
            elif days_left < 30:
                sev_tags.append("expiring_cert")

            out = "\n".join(lines)
            return SkillResult(self.name, True, out, True, sev_tags)

        except ssl.SSLCertVerificationError as e:
            return SkillResult(self.name, True,
                               f"**SSL Certificate** `{host}:{port}`\n  [CRITICAL] Cert verification failed: {e}",
                               True, ["ssl_cert", "cert_error", host])
        except ssl.SSLError as e:
            return SkillResult(self.name, False, f"⚠ SSL error: {e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return SkillResult(self.name, False, f"⚠ Connection failed: {e}")


class HttpHeaderAnalyzerSkill(Skill):
    """Real HTTP/HTTPS header fetch and security analysis."""
    name             = "http_header_analyzer"
    description      = "Fetch HTTP headers and audit security posture (HSTS, CSP, X-Frame, etc.)"
    usage            = "http_header_analyzer <url>"
    trigger_patterns = ["http headers", "security headers", "check hsts", "header analysis"]

    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("HSTS",      True),
        "Content-Security-Policy":   ("CSP",       True),
        "X-Frame-Options":           ("X-Frame",   True),
        "X-Content-Type-Options":    ("XCTO",      True),
        "Referrer-Policy":           ("Ref-Policy",True),
        "Permissions-Policy":        ("Perm-Policy",False),
        "X-XSS-Protection":          ("XSS-Prot", False),
    }

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        url = args.strip()
        if not url:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            req = urllib.request.Request(url, method="HEAD",
                headers={"User-Agent": "OMNIKON-SecOps/1.0.2"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers = dict(resp.headers)
                status  = resp.status
                final   = resp.url

            lines = [f"**HTTP Header Analysis** `{url}`\n",
                     f"  Status  : {status}",
                     f"  Final   : {final}" if final != url else "",
                     f"  Server  : {headers.get('server', 'hidden')}",
                     f"  Powered : {headers.get('x-powered-by', 'hidden')}",
                     ""]
            lines = [l for l in lines if l != ""]

            missing_critical = []
            lines.append("  Security Headers:")
            for hdr, (label, critical) in self.SECURITY_HEADERS.items():
                val     = headers.get(hdr, headers.get(hdr.lower(), None))
                present = val is not None
                flag    = "✓" if present else ("✗ [CRITICAL]" if critical else "✗ [INFO]")
                display = val[:80] if val else "absent"
                lines.append(f"    {flag} {label:<15} {display}")
                if not present and critical:
                    missing_critical.append(label)

            if missing_critical:
                lines.append(f"\n  [CRITICAL] Missing: {', '.join(missing_critical)}")

            out = "\n".join(lines)
            tags = ["http_headers", url.split("/")[2]]
            if missing_critical:
                tags.append("missing_security_headers")
            return SkillResult(self.name, True, out, True, tags)

        except urllib.error.URLError as e:
            return SkillResult(self.name, False, f"⚠ Request failed: {e}")
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE SKILLS
# ─────────────────────────────────────────────────────────────────────────────

class CveLookupSkill(Skill):
    """Real CVE data from NVD (NIST) public API — no key required."""
    name             = "cve_lookup"
    description      = "Look up CVE details from NVD/NIST (real API, no key needed)"
    usage            = "cve_lookup <CVE-YYYY-NNNNN>"
    trigger_patterns = ["cve lookup", "vulnerability details", "check cve", "nvd lookup"]

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        cve_id = args.strip().upper()
        if not re.match(r"CVE-\d{4}-\d+", cve_id):
            return SkillResult(self.name, False, f"⚠ Invalid format. Usage: {self.usage}")

        url = f"{self.NVD_URL}?cveId={cve_id}"
        try:
            req = urllib.request.Request(url,
                headers={"User-Agent": "OMNIKON-SecOps/1.0.2"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return SkillResult(self.name, True, f"No NVD data found for {cve_id}")

            cve   = vulns[0]["cve"]
            desc  = next((d["value"] for d in cve.get("descriptions", [])
                          if d.get("lang") == "en"), "No description")

            # CVSS score
            metrics    = cve.get("metrics", {})
            cvss_score = "N/A"
            cvss_sev   = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m          = metrics[key][0]["cvssData"]
                    cvss_score = m.get("baseScore", "N/A")
                    cvss_sev   = m.get("baseSeverity", "N/A")
                    break

            published = cve.get("published", "")[:10]
            modified  = cve.get("lastModified", "")[:10]
            refs      = [r["url"] for r in cve.get("references", [])[:3]]

            sev_tag = ""
            try:
                if float(cvss_score) >= 9.0:
                    sev_tag = "[CRITICAL]"
                elif float(cvss_score) >= 7.0:
                    sev_tag = "[HIGH]"
                elif float(cvss_score) >= 4.0:
                    sev_tag = "[MEDIUM]"
                else:
                    sev_tag = "[LOW]"
            except (ValueError, TypeError):
                pass

            lines = [
                f"**CVE** `{cve_id}` {sev_tag}\n",
                f"  CVSS Score  : {cvss_score} ({cvss_sev})",
                f"  Published   : {published}",
                f"  Last Mod    : {modified}",
                f"  Description : {desc[:400]}",
            ]
            if refs:
                lines.append("  References  :")
                for r in refs:
                    lines.append(f"    {r}")

            out = "\n".join(lines)
            return SkillResult(self.name, True, out, True,
                               ["cve", cve_id, cvss_sev.lower()])

        except urllib.error.URLError as e:
            return SkillResult(self.name, False, f"⚠ NVD API error: {e}")
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


class IpReputationSkill(Skill):
    """
    Real IP reputation check via:
    1. AbuseIPDB public API (requires ABUSEIPDB_API_KEY env var)
    2. Fallback: check against known blocklists via DNS-based BL (DNSBL)
    """
    name             = "ip_reputation"
    description      = "IP reputation: AbuseIPDB + DNSBL checks (set ABUSEIPDB_API_KEY)"
    usage            = "ip_reputation <ip_address>"
    trigger_patterns = ["ip reputation", "is this ip malicious", "check ip", "ip abuse"]

    DNSBLS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "xbl.spamhaus.org",
    ]

    def _dnsbl_check(self, ip: str) -> list[str]:
        try:
            parts = ipaddress.ip_address(ip).reverse_pointer.replace(".in-addr.arpa", "")
        except ValueError:
            return []
        listed_on = []
        for bl in self.DNSBLS:
            query = f"{parts}.{bl}"
            try:
                socket.getaddrinfo(query, None)
                listed_on.append(bl)
            except socket.gaierror:
                pass
        return listed_on

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        ip = args.strip()
        if not ip:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return SkillResult(self.name, False, f"⚠ Invalid IP: {ip}")

        lines = [f"**IP Reputation** `{ip}`\n"]

        # AbuseIPDB
        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if api_key:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
                req = urllib.request.Request(url, headers={
                    "Key": api_key, "Accept": "application/json",
                    "User-Agent": "OMNIKON-SecOps/1.0.2"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    d    = json.loads(resp.read())["data"]
                    conf = d.get("abuseConfidenceScore", 0)
                    rpts = d.get("totalReports",         0)
                    ctry = d.get("countryCode",          "??")
                    isp  = d.get("isp",                  "unknown")
                    tag  = "[CRITICAL]" if conf >= 75 else ("[WARN]" if conf >= 25 else "[CLEAN]")
                    lines += [
                        f"  AbuseIPDB: {tag} confidence={conf}%  reports={rpts}",
                        f"  Country  : {ctry}  ISP: {isp}",
                    ]
            except Exception as e:
                lines.append(f"  AbuseIPDB: unavailable ({e})")
        else:
            lines.append("  AbuseIPDB: set ABUSEIPDB_API_KEY for live scoring")

        # DNSBL
        listed = self._dnsbl_check(ip)
        if listed:
            lines.append(f"  [CRITICAL] DNSBL listed on: {', '.join(listed)}")
        else:
            lines.append(f"  DNSBL: not listed on {len(self.DNSBLS)} checked blocklists")

        out  = "\n".join(lines)
        tags = ["ip_reputation", ip]
        if listed:
            tags.append("blacklisted")
        return SkillResult(self.name, True, out, True, tags)


class HashLookupSkill(Skill):
    """
    Compute file/string hash AND query VirusTotal API if key is set.
    Falls back to local hash computation only.
    """
    name             = "hash_lookup"
    description      = "Hash a string/file (MD5/SHA1/SHA256) and optionally query VirusTotal"
    usage            = "hash_lookup <text_or_filepath> [md5|sha1|sha256]"
    trigger_patterns = ["hash lookup", "virustotal", "file hash", "malware hash", "check hash"]
    VT_URL           = "https://www.virustotal.com/api/v3/files/"

    def _hash_data(self, data: bytes) -> dict[str, str]:
        return {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _vt_lookup(self, sha256: str) -> dict[str, Any] | None:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return None
        try:
            req = urllib.request.Request(
                f"{self.VT_URL}{sha256}",
                headers={"x-apikey": api_key, "User-Agent": "OMNIKON-SecOps/1.0.2"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"not_found": True}
            return None
        except Exception:
            return None

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split()
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        target   = parts[0]
        req_algo = parts[1].lower() if len(parts) > 1 else "sha256"

        # Try to read as file, else treat as literal string
        p = Path(target)
        if p.exists() and p.is_file():
            data = p.read_bytes()
            src  = f"file:{target}"
        else:
            data = target.encode()
            src  = f"string:{target[:50]}"

        hashes = self._hash_data(data)
        lines  = [
            f"**Hash Lookup** ({src})\n",
            f"  MD5    : {hashes['md5']}",
            f"  SHA1   : {hashes['sha1']}",
            f"  SHA256 : {hashes['sha256']}",
        ]

        # VirusTotal
        vt = self._vt_lookup(hashes["sha256"])
        if vt is None:
            lines.append("  VT     : set VIRUSTOTAL_API_KEY for live lookups")
        elif vt.get("not_found"):
            lines.append("  VT     : not found in VirusTotal database")
        else:
            try:
                stats = vt["data"]["attributes"]["last_analysis_stats"]
                mal   = stats.get("malicious", 0)
                total = sum(stats.values())
                tag   = "[CRITICAL]" if mal > 5 else ("[WARN]" if mal > 0 else "[CLEAN]")
                lines.append(f"  VT     : {tag} {mal}/{total} engines flagged malicious")
            except (KeyError, TypeError):
                lines.append("  VT     : response parse error")

        out  = "\n".join(lines)
        tags = ["hash", hashes["sha256"][:16]]
        return SkillResult(self.name, True, out, True, tags)


class IocExtractorSkill(Skill):
    """Extract all IOCs (IPs, domains, hashes, CVEs, emails, URLs) from text."""
    name             = "ioc_extractor"
    description      = "Extract IOCs from text: IPs, domains, hashes, CVEs, emails, URLs"
    usage            = "ioc_extractor <text>"
    trigger_patterns = ["extract ioc", "find indicators", "ioc extract", "parse indicators"]

    _PATTERNS = {
        "IPv4":   re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "IPv6":   re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        "Domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|onion)\b"),
        "URL":    re.compile(r"https?://[^\s\"'<>]{8,200}"),
        "Email":  re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
        "MD5":    re.compile(r"\b[0-9a-fA-F]{32}\b"),
        "SHA1":   re.compile(r"\b[0-9a-fA-F]{40}\b"),
        "SHA256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
        "CVE":    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    }

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        if not args.strip():
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        results: dict[str, list[str]] = {}
        for ioc_type, pattern in self._PATTERNS.items():
            found = sorted(set(pattern.findall(args)))
            if found:
                results[ioc_type] = found

        if not results:
            return SkillResult(self.name, True, "No IOCs found in provided text.")

        total = sum(len(v) for v in results.values())
        lines = [f"**IOC Extraction** — {total} indicators found\n"]
        for ioc_type, items in results.items():
            lines.append(f"  {ioc_type} ({len(items)}):")
            for item in items[:20]:
                lines.append(f"    {item}")
            if len(items) > 20:
                lines.append(f"    … and {len(items) - 20} more")

        # Store each IOC type to archive
        all_iocs = [item for items in results.values() for item in items]
        out = "\n".join(lines)
        return SkillResult(self.name, True, out, True,
                           ["ioc_extraction", f"count:{total}"])


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS SKILLS
# ─────────────────────────────────────────────────────────────────────────────

class LogAnalyzerSkill(Skill):
    """Deep log analysis: brute-force, injections, anomalies, timeline."""
    name             = "log_analyzer"
    description      = "Deep log analysis: brute-force, injections, recon, timeline correlation"
    usage            = "log_analyzer <log text>"
    trigger_patterns = ["analyze log", "parse log", "check logs", "log analysis", "siem"]

    _IP     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _TS     = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?")
    _STATUS = re.compile(r"\b([1-5]\d{2})\b")
    _SQL_INJ= re.compile(r"(?i)(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|INSERT\s+INTO|--\s|xp_cmdshell)")
    _XSS    = re.compile(r"(?i)(<script|javascript:|onerror=|onload=|alert\()")
    _PATH_T = re.compile(r"(?i)(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|\/proc\/)")
    _SCANNER= re.compile(r"(?i)(nikto|nmap|sqlmap|masscan|zap|burpsuite|nessus|openvas|nuclei)")

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        if not args.strip():
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        lines     = args.strip().splitlines()
        ips       = sorted(set(self._IP.findall(args)))
        timestamps= sorted(set(self._TS.findall(args)))

        # Brute force detection
        ip_failures: dict[str, int] = {}
        ip_successes: dict[str, int]= {}
        for line in lines:
            line_ips = self._IP.findall(line)
            if re.search(r"(?i)(FAILED_LOGIN|authentication failure|invalid password|unauthorized)", line):
                for ip in line_ips:
                    ip_failures[ip] = ip_failures.get(ip, 0) + 1
            if re.search(r"(?i)(LOGIN_SUCCESS|authenticated|session opened)", line):
                for ip in line_ips:
                    ip_successes[ip] = ip_successes.get(ip, 0) + 1

        # Attack pattern detection
        sqli_lines  = [l for l in lines if self._SQL_INJ.search(l)]
        xss_lines   = [l for l in lines if self._XSS.search(l)]
        path_lines  = [l for l in lines if self._PATH_T.search(l)]
        scanner_hits= [l for l in lines if self._SCANNER.search(l)]

        # HTTP status distribution
        status_counts: dict[str, int] = {}
        for s in self._STATUS.findall(args):
            status_counts[s] = status_counts.get(s, 0) + 1

        # 4xx/5xx spike detection (>20% error rate)
        total_reqs = sum(status_counts.values())
        errors_4xx = sum(v for k, v in status_counts.items() if k.startswith("4"))
        errors_5xx = sum(v for k, v in status_counts.items() if k.startswith("5"))

        findings = []

        # Brute force
        for ip, cnt in ip_failures.items():
            tag = "[CRITICAL]" if cnt >= 5 else "[WARN]"
            succ_note = f" ({ip_successes.get(ip, 0)} success after)" if ip in ip_successes else ""
            findings.append(f"{tag} Brute-force: {cnt} failures from {ip}{succ_note}")

        # Injection attacks
        if sqli_lines:
            findings.append(f"[CRITICAL] SQL Injection attempts: {len(sqli_lines)} lines")
            findings.append(f"  Sample: {sqli_lines[0][:120]}")
        if xss_lines:
            findings.append(f"[CRITICAL] XSS attempts: {len(xss_lines)} lines")
        if path_lines:
            findings.append(f"[HIGH] Path traversal attempts: {len(path_lines)} lines")
        if scanner_hits:
            scanners = set(self._SCANNER.search(l).group(1) for l in scanner_hits if self._SCANNER.search(l))
            findings.append(f"[WARN] Security scanner detected: {', '.join(scanners)}")

        # Error rates
        if total_reqs > 0:
            err_pct = (errors_4xx + errors_5xx) / total_reqs * 100
            if err_pct > 30:
                findings.append(f"[WARN] High error rate: {err_pct:.1f}% ({errors_4xx} 4xx, {errors_5xx} 5xx)")

        summary_lines = [
            f"**Log Analysis** — {len(lines)} lines, {len(ips)} unique IPs\n",
        ]
        if timestamps:
            summary_lines.append(f"  Time range  : {timestamps[0]} → {timestamps[-1]}")
        if ips:
            summary_lines.append(f"  Source IPs  : {', '.join(ips[:10])}" +
                                  (f" … +{len(ips)-10}" if len(ips) > 10 else ""))
        if status_counts:
            top_status = sorted(status_counts.items(), key=lambda x: -x[1])[:5]
            summary_lines.append(f"  HTTP Status : {', '.join(f'{k}×{v}' for k,v in top_status)}")

        if findings:
            summary_lines.append("\n  **Findings:**")
            summary_lines.extend(f"  {f}" for f in findings)
        else:
            summary_lines.append("\n  ✓ No anomalies detected")

        out  = "\n".join(summary_lines)
        tags = ["log_analysis"]
        if sqli_lines:  tags.append("sql_injection")
        if xss_lines:   tags.append("xss")
        if ip_failures: tags.append("brute_force")
        return SkillResult(self.name, True, out, True, tags)


class VulnerabilityScorerSkill(Skill):
    """Score a system description against CVSS and OWASP criteria using DeepSeek."""
    name             = "vulnerability_scorer"
    description      = "Score a finding using CVSS v3.1 criteria and OWASP risk rating"
    usage            = "vulnerability_scorer <finding description>"
    trigger_patterns = ["score vulnerability", "cvss score", "risk rating", "assess vulnerability"]

    SYSTEM_PROMPT = """You are a CVSS v3.1 vulnerability scoring expert.
Given a vulnerability description, output ONLY valid JSON in this exact format:
{
  "cvss_score": 7.5,
  "cvss_severity": "HIGH",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "owasp_category": "A03:2021 - Injection",
  "attack_vector": "Network",
  "attack_complexity": "Low",
  "privileges_required": "None",
  "confidentiality_impact": "High",
  "integrity_impact": "None",
  "availability_impact": "None",
  "remediation_priority": "Critical",
  "recommended_fix": "One sentence fix recommendation"
}"""

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        if not args.strip():
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        try:
            raw = call_deepseek(
                self.SYSTEM_PROMPT,
                [{"role": "user", "content": f"Score this vulnerability:\n{args[:2000]}"}],
                max_tokens=512, temperature=0.1,
            )
            # Parse JSON from response
            json_match = re.search(r"\{[\s\S]+\}", raw)
            if not json_match:
                return SkillResult(self.name, False, f"⚠ Could not parse scoring response")
            scored = json.loads(json_match.group())

            lines = [
                f"**Vulnerability Score**\n",
                f"  CVSS Score  : {scored.get('cvss_score', 'N/A')} ({scored.get('cvss_severity', 'N/A')})",
                f"  CVSS Vector : {scored.get('cvss_vector', 'N/A')}",
                f"  OWASP       : {scored.get('owasp_category', 'N/A')}",
                f"  Attack Vec  : {scored.get('attack_vector', 'N/A')}",
                f"  Complexity  : {scored.get('attack_complexity', 'N/A')}",
                f"  Privs Req'd : {scored.get('privileges_required', 'N/A')}",
                f"  C/I/A Impact: {scored.get('confidentiality_impact','?')}/{scored.get('integrity_impact','?')}/{scored.get('availability_impact','?')}",
                f"  Priority    : {scored.get('remediation_priority', 'N/A')}",
                f"  Fix         : {scored.get('recommended_fix', 'N/A')}",
            ]
            out = "\n".join(lines)
            return SkillResult(self.name, True, out, True,
                               ["vuln_score", scored.get("cvss_severity", "").lower()])
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ Scoring failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY SKILLS
# ─────────────────────────────────────────────────────────────────────────────

class SummarizerSkill(Skill):
    name             = "summarizer"
    description      = "Summarize text using DeepSeek"
    usage            = "summarizer <text>"
    trigger_patterns = ["summarize", "tldr", "condense"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        try:
            s = call_deepseek("Return only a concise summary, no preamble.",
                              [{"role":"user","content":f"Summarize:\n{args[:6000]}"}],
                              max_tokens=512, temperature=0.3)
            return SkillResult(self.name, True, f"**Summary:**\n{s}", True, ["summary"])
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


class MemoryWriterSkill(Skill):
    name             = "memory_writer"
    description      = "Write a fact to long-term memory"
    usage            = "memory_writer <text>"
    trigger_patterns = ["remember this", "save to memory", "note this"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        e = mm.archive.store(args.strip(), source="skill_memory_writer", tags=["fact"])
        return SkillResult(self.name, True, f"✓ Stored → `{e.id}`")


# ─────────────────────────────────────────────────────────────────────────────
# UI-ALIGNED SKILLS  (matching cybersec-dashboard.jsx tool set)
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityAssessmentSkill(Skill):
    """
    Full vulnerability assessment: port scan → banner grab → CVE correlation.
    Maps to UI tool: vuln-assess
    """
    name             = "vulnerability_assessment"
    description      = "Full assessment: port scan + service fingerprint + CVE lookup per service"
    usage            = "vulnerability_assessment <host>"
    trigger_patterns = ["vulnerability assessment", "full scan", "assess target", "pentest"]

    NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=3"

    def _service_cves(self, service: str) -> list[dict]:
        """Query NVD for CVEs matching service name."""
        if not service or service in ("unknown", "http-alt"):
            return []
        try:
            url = self.NVD_SEARCH.format(kw=urllib.parse.quote(service))
            req = urllib.request.Request(url, headers={"User-Agent": "OMNIKON-SecOps/1.0.2"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data   = json.loads(resp.read())
                vulns  = data.get("vulnerabilities", [])
                result = []
                for v in vulns[:3]:
                    cve  = v.get("cve", {})
                    cid  = cve.get("id", "")
                    desc = next((d["value"] for d in cve.get("descriptions", [])
                                 if d.get("lang") == "en"), "")[:120]
                    metrics = cve.get("metrics", {})
                    score   = "N/A"
                    sev     = "N/A"
                    for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                        if metrics.get(key):
                            score = metrics[key][0]["cvssData"].get("baseScore","N/A")
                            sev   = metrics[key][0]["cvssData"].get("baseSeverity","N/A")
                            break
                    result.append({"id": cid, "severity": sev, "score": score, "desc": desc})
                return result
        except Exception:
            return []

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        host = args.strip()
        if not host:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        # 1. Resolve
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return SkillResult(self.name, False, f"⚠ Cannot resolve {host}: {e}")

        # 2. Port scan common ports
        COMMON_PORTS = [21,22,23,25,53,80,110,143,389,443,445,
                        3306,3389,5432,6379,8080,8443,27017,5900]
        open_ports: list[tuple[int, str, str]] = []

        def _scan(port: int) -> tuple[int, bool, str]:
            try:
                with socket.create_connection((ip, port), timeout=1.2) as s:
                    s.settimeout(0.3)
                    try:
                        banner = s.recv(256).decode(errors="replace").strip()[:60]
                    except Exception:
                        banner = ""
                    return port, True, banner
            except Exception:
                return port, False, ""

        with ThreadPoolExecutor(max_workers=30) as ex:
            for port, is_open, banner in ex.map(_scan, COMMON_PORTS):
                if is_open:
                    svc = _well_known_service(port)
                    open_ports.append((port, svc, banner))

        # 3. CVE lookup per service
        all_cves: list[dict] = []
        checked_svcs: set[str] = set()
        for _, svc, _ in open_ports[:5]:
            if svc and svc not in checked_svcs and svc != "unknown":
                cves = self._service_cves(svc)
                all_cves.extend(cves)
                checked_svcs.add(svc)

        # 4. Risk level
        critical_count = sum(1 for c in all_cves if str(c.get("score","0")) and
                             float(str(c.get("score","0")).replace("N/A","0") or "0") >= 9.0)
        risk_level = "critical" if critical_count > 0 else (
                     "high"     if len(all_cves) > 3 else (
                     "medium"   if open_ports else "low"))

        lines = [
            f"**Vulnerability Assessment** `{host}` ({ip})\n",
            f"  Risk Level  : [{risk_level.upper()}]",
            f"  Open Ports  : {len(open_ports)}",
            f"  CVEs Found  : {len(all_cves)} (via NVD keyword search per service)",
            "",
        ]
        if open_ports:
            lines.append("  **Open Ports & Services:**")
            for port, svc, banner in open_ports:
                b = f" — `{banner}`" if banner else ""
                lines.append(f"    {port:5d}/tcp  {svc:<15}{b}")

        if all_cves:
            lines.append("\n  **Related CVEs (NVD):**")
            for c in all_cves[:8]:
                tag = "[CRITICAL]" if float(str(c['score']).replace("N/A","0") or "0") >= 9.0 else "[HIGH]" if float(str(c['score']).replace("N/A","0") or "0") >= 7.0 else "[INFO]"
                lines.append(f"    {tag} {c['id']} CVSS:{c['score']} — {c['desc']}")
        else:
            lines.append("  No directly correlated CVEs found for detected services.")

        out = "\n".join(lines)
        return SkillResult(self.name, True, out, True,
                           ["vuln_assessment", host, risk_level, f"ports:{len(open_ports)}"])


class NetworkReconSkill(Skill):
    """
    Network reconnaissance: CIDR sweep, host discovery, OS hints.
    Maps to UI tool: network-recon
    """
    name             = "network_recon"
    description      = "Network recon: CIDR host discovery, open service sweep, topology mapping"
    usage            = "network_recon <cidr_or_host>  e.g. 192.168.1.0/24 or 10.0.0.1"
    trigger_patterns = ["network recon", "network scan", "host discovery", "cidr scan", "topology map"]
    MAX_HOSTS        = 64

    def _ping(self, ip: str) -> bool:
        """ICMP ping via subprocess (works on Linux/macOS)."""
        try:
            r = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                capture_output=True, timeout=3
            )
            return r.returncode == 0
        except Exception:
            return False

    def _tcp_probe(self, ip: str, ports: list[int] = None) -> list[int]:
        """Quick TCP probe to detect live hosts."""
        ports = ports or [22, 80, 443, 445, 3389]
        open_p = []
        for port in ports:
            try:
                with socket.create_connection((str(ip), port), timeout=0.8):
                    open_p.append(port)
            except Exception:
                pass
        return open_p

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        target = args.strip()
        if not target:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        # Parse as CIDR or single host
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts   = list(network.hosts())[:self.MAX_HOSTS]
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                hosts = [ipaddress.ip_address(ip)]
            except Exception as e:
                return SkillResult(self.name, False, f"⚠ Cannot parse target: {e}")

        lines = [f"**Network Recon** `{target}` — scanning {len(hosts)} host(s)\n"]

        live_hosts: list[dict] = []

        def _probe_host(ip: ipaddress.IPv4Address) -> dict | None:
            ip_str = str(ip)
            # Try TCP probe first (faster than ICMP in many envs)
            open_ports = self._tcp_probe(ip_str)
            if not open_ports:
                # Fall back to ICMP ping
                if not self._ping(ip_str):
                    return None
            # Reverse DNS
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
            except Exception:
                hostname = ""
            return {
                "ip": ip_str,
                "hostname": hostname,
                "open_ports": open_ports,
            }

        with ThreadPoolExecutor(max_workers=30) as ex:
            for result in ex.map(_probe_host, hosts):
                if result:
                    live_hosts.append(result)

        if not live_hosts:
            lines.append("  No live hosts discovered.")
        else:
            lines.append(f"  **Live Hosts ({len(live_hosts)}):**")
            for h in live_hosts[:30]:
                hostname = f" ({h['hostname']})" if h["hostname"] else ""
                ports    = ", ".join(str(p) for p in h["open_ports"])
                services = ", ".join(_well_known_service(p) for p in h["open_ports"])
                lines.append(f"    {h['ip']:<17}{hostname}")
                if h["open_ports"]:
                    lines.append(f"      Services: {services} (ports {ports})")

        # Topology summary
        total_services = sum(len(h["open_ports"]) for h in live_hosts)
        risk = "high" if any(p in [23,21,445,3389] for h in live_hosts for p in h["open_ports"]) else "medium"
        lines.extend([
            "",
            f"  **Topology Summary:**",
            f"    Live hosts      : {len(live_hosts)}/{len(hosts)}",
            f"    Exposed services: {total_services}",
            f"    Risk level      : [{risk.upper()}]",
        ])

        out = "\n".join(lines)
        return SkillResult(self.name, True, out, True,
                           ["network_recon", target, f"hosts:{len(live_hosts)}"])


class DnsSecuritySkill(Skill):
    """
    Full DNS security analysis: DNSSEC, zone transfer, SPF/DKIM/DMARC, subdomain enum.
    Maps to UI tool: dns-analysis
    """
    name             = "dns_security"
    description      = "DNS security: DNSSEC, zone transfer, SPF/DKIM/DMARC, MX/NS/TXT records"
    usage            = "dns_security <domain>"
    trigger_patterns = ["dns security", "dnssec", "zone transfer", "email security", "spf dkim dmarc", "subdomain"]

    def _dig(self, domain: str, rec_type: str) -> list[str]:
        try:
            r = subprocess.run(["dig", "+short", rec_type, domain],
                               capture_output=True, text=True, timeout=10)
            return [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        except FileNotFoundError:
            return []
        except Exception:
            return []

    def _resolve(self, domain: str, rec_type: str) -> list[str]:
        """Stdlib DNS fallback when dig unavailable."""
        results = []
        try:
            if rec_type == "A":
                results = [socket.gethostbyname(domain)]
            elif rec_type == "MX":
                # Try dig first, stdlib has no MX
                pass
        except Exception:
            pass
        return results

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        domain = args.strip().lower()
        if not domain:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        lines = [f"**DNS Security Analysis** `{domain}`\n"]

        # A records
        a_recs = self._dig(domain, "A") or self._resolve(domain, "A")
        lines.append(f"  A records    : {', '.join(a_recs) if a_recs else 'none'}")

        # MX records
        mx_recs = self._dig(domain, "MX")
        lines.append(f"  MX records   : {', '.join(mx_recs[:3]) if mx_recs else 'none'}")

        # NS records
        ns_recs = self._dig(domain, "NS")
        lines.append(f"  NS records   : {', '.join(ns_recs[:3]) if ns_recs else 'none'}")

        # SPF (TXT record containing v=spf1)
        txt_recs = self._dig(domain, "TXT")
        spf  = next((r for r in txt_recs if "v=spf1" in r.lower()), None)
        dmarc_recs = self._dig(f"_dmarc.{domain}", "TXT")
        dmarc = next((r for r in dmarc_recs if "v=dmarc1" in r.lower()), None)
        # DKIM (common selector)
        dkim_recs = self._dig(f"default._domainkey.{domain}", "TXT")
        dkim = next((r for r in dkim_recs if "v=dkim1" in r.lower()), None)

        lines.extend([
            "",
            "  **Email Security:**",
            f"    SPF   : {'✓ ' + spf[:80]  if spf  else '✗ [WARN] Missing SPF record'}",
            f"    DMARC : {'✓ ' + dmarc[:80] if dmarc else '✗ [WARN] Missing DMARC record'}",
            f"    DKIM  : {'✓ present'        if dkim  else '⚠ default selector not found (check with actual selector)'}",
        ])

        # Zone transfer attempt
        zt_vulnerable = False
        if ns_recs:
            ns_host = ns_recs[0].rstrip(".")
            try:
                r = subprocess.run(["dig", "+short", "AXFR", domain, f"@{ns_host}"],
                                   capture_output=True, text=True, timeout=8)
                if r.stdout.strip() and len(r.stdout.strip().splitlines()) > 3:
                    zt_vulnerable = True
            except Exception:
                pass

        lines.append(f"\n  Zone Transfer: {'[CRITICAL] ALLOWED — data exposed' if zt_vulnerable else '✓ Restricted'}")

        # DNSSEC
        dnssec_recs = self._dig(domain, "DNSKEY")
        lines.append(f"  DNSSEC       : {'✓ Enabled' if dnssec_recs else '✗ [INFO] Not enabled'}")

        # Risk summary
        issues = []
        if not spf:   issues.append("no SPF")
        if not dmarc: issues.append("no DMARC")
        if zt_vulnerable: issues.append("zone transfer allowed")
        risk = "high" if zt_vulnerable else ("medium" if issues else "low")
        lines.extend([
            "",
            f"  **Risk Level : [{risk.upper()}]**",
            f"  Issues       : {', '.join(issues) if issues else 'none detected'}",
        ])

        out = "\n".join(lines)
        tags = ["dns_security", domain]
        if zt_vulnerable: tags.append("zone_transfer")
        if not spf:       tags.append("missing_spf")
        return SkillResult(self.name, True, out, True, tags)


class WebAppScannerSkill(Skill):
    """
    Active OWASP Top 10 web application scan.
    Maps to UI tool: web-app-scan
    Real HTTP probes for SQLi, XSS, header injection, open redirect, info disclosure.
    """
    name             = "web_app_scanner"
    description      = "OWASP Top 10 active scan: SQLi probe, XSS probe, headers, info disclosure"
    usage            = "web_app_scanner <url> [auth_header]"
    trigger_patterns = ["web app scan", "owasp scan", "web scan", "xss scan", "sqli scan"]

    SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--"]
    XSS_PAYLOADS  = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]

    def _req(self, url: str, headers: dict | None = None, path: str = "") -> tuple[int, dict, str]:
        full_url = url.rstrip("/") + path if path else url
        try:
            req = urllib.request.Request(full_url, method="GET",
                headers={"User-Agent": "OMNIKON-SecOps/1.0.2", **(headers or {})})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status, dict(r.headers), r.read(8192).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception:
            return 0, {}, ""

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split(None, 1)
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        url         = parts[0]
        auth_header = parts[1] if len(parts) > 1 else None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        extra_headers = {"Authorization": auth_header} if auth_header else {}

        findings: list[dict] = []
        lines    = [f"**Web Application Scan** `{url}`\n"]

        # 1. Baseline request
        status, resp_headers, body = self._req(url, extra_headers)
        if status == 0:
            return SkillResult(self.name, False, f"⚠ Cannot connect to {url}")

        lines.append(f"  Baseline : HTTP {status}")

        # 2. Security headers (A05:2021 Security Misconfiguration)
        SEC_HDRS = ["strict-transport-security","content-security-policy",
                    "x-frame-options","x-content-type-options"]
        missing_hdrs = [h for h in SEC_HDRS if h not in {k.lower(): v for k,v in resp_headers.items()}]
        if missing_hdrs:
            findings.append({"type": "A05:MissingHeaders", "severity": "medium",
                             "detail": f"Missing: {', '.join(missing_hdrs)}"})

        # 3. Server/tech info disclosure (A05)
        server = resp_headers.get("Server", resp_headers.get("server", ""))
        powered = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
        if server: findings.append({"type": "A05:InfoDisclosure", "severity": "low",
                                     "detail": f"Server header: {server}"})
        if powered: findings.append({"type": "A05:InfoDisclosure", "severity": "low",
                                      "detail": f"X-Powered-By: {powered}"})

        # 4. SQLi probe (A03:2021 Injection)
        for payload in self.SQLI_PAYLOADS[:2]:
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            sc, _, bd = self._req(test_url, extra_headers)
            error_indicators = ["sql syntax", "mysql_fetch", "ora-", "postgresql",
                                 "unclosed quotation", "sqlstate", "syntax error"]
            if any(ind in bd.lower() for ind in error_indicators):
                findings.append({"type": "A03:SQLi", "severity": "critical",
                                 "detail": f"SQL error returned for payload: {payload[:30]}"})
                break

        # 5. XSS probe (A03:2021)
        for payload in self.XSS_PAYLOADS[:1]:
            test_url = f"{url}?q={urllib.parse.quote(payload)}"
            sc, _, bd = self._req(test_url, extra_headers)
            if payload.lower().replace(" ", "") in bd.lower().replace(" ", ""):
                findings.append({"type": "A03:XSS", "severity": "high",
                                 "detail": f"Reflected XSS: payload echoed back"})
                break

        # 6. Common sensitive paths (A05 / A01)
        for path in ["/.env", "/admin", "/phpinfo.php", "/.git/HEAD",
                     "/config.php", "/wp-admin", "/api/v1/users"]:
            sc, _, bd = self._req(url, extra_headers, path)
            if sc in (200, 403) and sc != 404:
                sev = "high" if path in ("/.env","/.git/HEAD","/.git/config") else "medium"
                findings.append({"type": "A05:SensitivePath", "severity": sev,
                                 "detail": f"HTTP {sc} at {path}"})

        # 7. Open redirect (A01:BrokenAccessControl)
        test_url = f"{url}?redirect=https://evil.example.com"
        sc, rdr_hdrs, _ = self._req(test_url, extra_headers)
        location = rdr_hdrs.get("Location", rdr_hdrs.get("location", ""))
        if sc in (301,302,307,308) and "evil.example.com" in location:
            findings.append({"type": "A01:OpenRedirect", "severity": "high",
                             "detail": "Open redirect to attacker-controlled URL"})

        # Summarise
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high     = sum(1 for f in findings if f["severity"] == "high")
        risk     = "critical" if critical > 0 else ("high" if high > 0 else
                   "medium" if findings else "low")

        lines.extend([
            f"  Risk Level : [{risk.upper()}]",
            f"  Findings   : {len(findings)} ({critical} critical, {high} high)",
            "",
            "  **Findings:**" if findings else "  ✓ No critical vulnerabilities detected",
        ])
        for f in findings:
            sev_tag = f"[{f['severity'].upper()}]"
            lines.append(f"    {sev_tag:<12} {f['type']:<25} {f['detail']}")

        out  = "\n".join(lines)
        tags = ["web_app_scan", url.split("/")[2]]
        if critical: tags.append("critical_vuln")
        return SkillResult(self.name, True, out, True, tags)


class ApiSecurityAuditSkill(Skill):
    """
    Real API security audit: auth check, rate limit detection, endpoint exposure, CORS.
    Maps to UI tool: api-security
    """
    name             = "api_security_audit"
    description      = "API security: auth check, rate limiting, CORS, info disclosure, common endpoints"
    usage            = "api_security_audit <base_url> [bearer_token]"
    trigger_patterns = ["api security", "api audit", "api scan", "rest api", "rate limiting"]

    COMMON_ENDPOINTS = [
        "/users", "/user", "/admin", "/api/users", "/api/v1/users",
        "/health", "/metrics", "/swagger.json", "/openapi.json",
        "/api-docs", "/.well-known/openid-configuration",
        "/actuator", "/actuator/env", "/graphql",
    ]

    def _req(self, url: str, headers: dict) -> tuple[int, dict, str]:
        try:
            req = urllib.request.Request(url, method="GET",
                headers={"User-Agent": "OMNIKON-SecOps/1.0.2", **headers})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status, dict(r.headers), r.read(4096).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception:
            return 0, {}, ""

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split(None, 1)
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        base_url = parts[0].rstrip("/")
        token    = parts[1] if len(parts) > 1 else None
        if not base_url.startswith(("http://","https://")):
            base_url = "https://" + base_url
        auth_hdr = {"Authorization": f"Bearer {token}"} if token else {}

        lines    = [f"**API Security Audit** `{base_url}`\n"]
        findings : list[str] = []

        # 1. Baseline
        status, headers, body = self._req(base_url, auth_hdr)
        lines.append(f"  Baseline : HTTP {status}")
        if status == 0:
            return SkillResult(self.name, False, f"⚠ Cannot connect to {base_url}")

        # 2. Authentication check — try without token
        if token:
            sc_noauth, _, _ = self._req(base_url, {})
            if sc_noauth == 200:
                findings.append("[CRITICAL] Endpoint accessible without authentication")
            elif sc_noauth in (401, 403):
                lines.append("  Auth     : ✓ Returns 401/403 without token")

        # 3. CORS check
        cors = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin",""))
        if cors == "*":
            findings.append("[HIGH] CORS: Access-Control-Allow-Origin: * (any origin allowed)")
        elif cors:
            lines.append(f"  CORS     : {cors}")

        # 4. Rate limiting headers
        rl_headers = ["x-ratelimit-limit","ratelimit-limit","x-rate-limit",
                      "retry-after","x-request-limit"]
        rl_found = any(h in {k.lower() for k in headers} for h in rl_headers)
        if not rl_found:
            findings.append("[MEDIUM] No rate-limiting headers detected")
        else:
            lines.append("  Rate-limit: ✓ Headers present")

        # 5. Common endpoint discovery
        exposed: list[str] = []
        def _probe(path: str) -> tuple[str, int]:
            sc, _, bd = self._req(f"{base_url}{path}", auth_hdr)
            return path, sc

        with ThreadPoolExecutor(max_workers=10) as ex:
            for path, sc in ex.map(lambda p: _probe(p), self.COMMON_ENDPOINTS):
                if sc in (200, 201):
                    sev = "critical" if any(s in path for s in ("actuator","env","admin","graphql")) else "medium"
                    exposed.append(f"    [{sev.upper():<8}] HTTP {sc}  {path}")

        if exposed:
            findings.append(f"[HIGH] {len(exposed)} sensitive endpoint(s) accessible")
            lines.extend(["", "  **Exposed Endpoints:**"] + exposed)

        # 6. Info disclosure via headers
        server  = headers.get("Server","")
        powered = headers.get("X-Powered-By","")
        if server:  findings.append(f"[LOW] Server header: {server}")
        if powered: findings.append(f"[LOW] X-Powered-By: {powered}")

        # 7. Content-Type enforcement
        ct = headers.get("Content-Type","")
        if body.strip().startswith("{") and "application/json" not in ct.lower():
            findings.append("[LOW] JSON response without Content-Type: application/json")

        risk = "critical" if any("[CRITICAL]" in f for f in findings) else \
               "high"     if any("[HIGH]"     in f for f in findings) else \
               "medium"   if findings else "low"

        lines.extend([
            "",
            f"  **Risk Level : [{risk.upper()}]**",
            f"  Issues       : {len(findings)}",
            "",
            "  **Findings:**" if findings else "  ✓ No critical API issues detected",
        ])
        lines.extend(f"    {f}" for f in findings)

        out  = "\n".join(lines)
        tags = ["api_security", base_url.split("/")[2]]
        if "critical" in risk: tags.append("critical_vuln")
        return SkillResult(self.name, True, out, True, tags)


class PasswordAuditSkill(Skill):
    """
    Password policy and authentication security audit.
    Maps to UI tool: password-audit
    Real checks: common password list, policy compliance, hash detection, lockout probe.
    """
    name             = "password_audit"
    description      = "Password security: policy check, hash detection, lockout probe, compliance"
    usage            = "password_audit <target_url_or_system> [policy_notes]"
    trigger_patterns = ["password audit", "password security", "brute force risk", "auth policy", "password policy"]

    WEAK_PASSWORDS = [
        "password","123456","admin","root","test","letmein","welcome","monkey","dragon","qwerty"
    ]
    HASH_PATTERNS = {
        "MD5":     re.compile(r"^\$1\$"),
        "SHA512":  re.compile(r"^\$6\$"),
        "bcrypt":  re.compile(r"^\$2[ab]\$"),
        "NTLM":    re.compile(r"^[0-9a-fA-F]{32}$"),
        "SHA256":  re.compile(r"^\$5\$"),
    }

    def _detect_hash_algo(self, sample: str) -> str:
        for algo, pat in self.HASH_PATTERNS.items():
            if pat.match(sample.strip()):
                return algo
        return "unknown/plaintext"

    def _probe_lockout(self, url: str) -> dict:
        """Attempt multiple login requests to detect lockout."""
        results = {"lockout_detected": False, "attempts_before_lockout": 0, "detail": ""}
        if not url.startswith(("http://","https://")):
            return results
        for i, pwd in enumerate(self.WEAK_PASSWORDS[:5], 1):
            try:
                data = urllib.parse.urlencode({"username":"admin","password":pwd}).encode()
                req  = urllib.request.Request(url, data=data, method="POST",
                    headers={"Content-Type":"application/x-www-form-urlencoded",
                             "User-Agent":"OMNIKON-SecOps/1.0.2"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status == 429:
                        results["lockout_detected"] = True
                        results["attempts_before_lockout"] = i
                        results["detail"] = f"HTTP 429 after {i} attempts"
                        break
                    body = r.read(512).decode(errors="replace").lower()
                    if any(x in body for x in ("locked","too many","blocked","captcha")):
                        results["lockout_detected"] = True
                        results["attempts_before_lockout"] = i
                        results["detail"] = f"Lockout keyword in response after {i} attempts"
                        break
            except Exception:
                break
        if not results["lockout_detected"] and i >= 4:
            results["detail"] = f"No lockout after {i} attempts — [CRITICAL] likely no lockout"
        return results

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts = args.strip().split(None, 1)
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        target      = parts[0]
        policy_notes= parts[1] if len(parts) > 1 else ""
        is_url      = target.startswith(("http://","https://"))

        lines    = [f"**Password Security Audit** `{target}`\n"]
        issues   : list[str] = []

        # 1. Policy analysis (via DeepSeek if policy provided, else heuristic)
        if policy_notes:
            try:
                analysis = call_deepseek(
                    "You are a security auditor. Analyse the password policy. "
                    "Respond with ONLY a JSON object: "
                    '{"min_length_ok": true/false, "complexity_ok": true/false, '
                    '"mfa_mentioned": true/false, "lockout_mentioned": true/false, '
                    '"issues": ["issue1", "issue2"]}',
                    [{"role":"user","content":f"Policy: {policy_notes}"}],
                    max_tokens=256, temperature=0.1,
                )
                json_m = re.search(r"\{[\s\S]+\}", analysis)
                if json_m:
                    pa = json.loads(json_m.group())
                    lines.append("  **Policy Analysis:**")
                    lines.append(f"    Min length OK : {'✓' if pa.get('min_length_ok') else '✗ [WARN]'}")
                    lines.append(f"    Complexity OK : {'✓' if pa.get('complexity_ok') else '✗ [WARN]'}")
                    lines.append(f"    MFA mentioned : {'✓' if pa.get('mfa_mentioned') else '✗ [WARN]'}")
                    lines.append(f"    Lockout policy: {'✓' if pa.get('lockout_mentioned') else '✗ [WARN]'}")
                    for issue in pa.get("issues", []):
                        issues.append(f"[MEDIUM] Policy: {issue}")
            except Exception:
                lines.append(f"  Policy notes: {policy_notes}")

        # 2. Hash detection if target looks like a hash string
        if re.match(r"^[\$a-fA-F0-9]", target) and len(target) in (32,40,60,128,106):
            algo = self._detect_hash_algo(target)
            weak = algo in ("MD5","NTLM")
            tag  = "[CRITICAL]" if weak else "[INFO]"
            lines.append(f"  Hash Algorithm: {tag} {algo}")
            if weak:
                issues.append(f"[CRITICAL] Weak hash algorithm: {algo} (crackable)")

        # 3. Lockout probe (if URL)
        if is_url:
            lockout = self._probe_lockout(target)
            if lockout["lockout_detected"]:
                lines.append(f"  Lockout Probe : ✓ Detected after {lockout['attempts_before_lockout']} attempt(s)")
            else:
                lines.append(f"  Lockout Probe : [CRITICAL] No account lockout detected — brute-force risk")
                issues.append("[CRITICAL] No lockout mechanism — brute-force feasible")

        # 4. SSL/TLS check for URL targets
        if is_url and target.startswith("https://"):
            lines.append("  Transport     : ✓ HTTPS in use")
        elif is_url:
            issues.append("[CRITICAL] HTTP (not HTTPS) — credentials sent in plaintext")
            lines.append("  Transport     : [CRITICAL] HTTP — credentials exposed in transit")

        # 5. Common attack vectors
        attack_vectors = [
            ("Credential Stuffing", "high",   "Use of previously breached username/password combos"),
            ("Brute Force",         "high",   "Automated guessing of weak/short passwords"),
            ("Password Spraying",   "medium", "Low-rate guessing of common passwords across accounts"),
        ]

        risk = "critical" if any("[CRITICAL]" in i for i in issues) else \
               "high"     if any("[HIGH]"     in i for i in issues) else \
               "medium"   if issues else "low"

        lines.extend([
            "",
            f"  **Risk Level : [{risk.upper()}]**",
            "",
            "  **Attack Vectors:**",
        ])
        for name, sev, desc in attack_vectors:
            lines.append(f"    [{sev.upper():<8}] {name:<22} — {desc}")

        if issues:
            lines.extend(["", "  **Issues:**"])
            lines.extend(f"    {i}" for i in issues)

        out  = "\n".join(lines)
        tags = ["password_audit", target[:40]]
        return SkillResult(self.name, True, out, True, tags)


class FirewallAuditorSkill(Skill):
    """
    Firewall rules analysis: parse iptables/nftables rules, detect over-permissive policies.
    Maps to UI tool: firewall-audit
    """
    name             = "firewall_auditor"
    description      = "Firewall rules audit: iptables/nftables parser, over-permissive detection, egress check"
    usage            = "firewall_auditor <paste iptables/nftables rules OR host_ip>"
    trigger_patterns = ["firewall audit", "firewall rules", "iptables", "nftables", "firewall check"]

    # Dangerous rule patterns
    DANGER_PATTERNS = [
        (re.compile(r"-s\s+0\.0\.0\.0/0.+--dport\s+22"),   "critical", "SSH open to 0.0.0.0/0"),
        (re.compile(r"-s\s+0\.0\.0\.0/0.+--dport\s+3389"), "critical", "RDP open to 0.0.0.0/0"),
        (re.compile(r"-s\s+0\.0\.0\.0/0.+--dport\s+21"),   "high",     "FTP open to 0.0.0.0/0"),
        (re.compile(r"-s\s+0\.0\.0\.0/0.+--dport\s+23"),   "critical", "Telnet open to 0.0.0.0/0"),
        (re.compile(r"-j\s+ACCEPT\s+-s\s+0\.0\.0\.0/0"),   "high",     "Blanket ACCEPT from any source"),
        (re.compile(r"policy\s+ACCEPT", re.I),              "medium",   "Default ACCEPT policy"),
        (re.compile(r"-A\s+FORWARD\s+-j\s+ACCEPT"),        "high",     "Unrestricted forwarding"),
        (re.compile(r"--dport\s+445.+-j\s+ACCEPT"),        "high",     "SMB/445 exposed"),
        (re.compile(r"--dport\s+1433.+-j\s+ACCEPT"),       "high",     "MSSQL/1433 exposed"),
        (re.compile(r"--dport\s+5432.+-j\s+ACCEPT"),       "medium",   "PostgreSQL/5432 exposed"),
    ]

    def _get_live_rules(self, host: str) -> str | None:
        """Attempt to grab iptables rules from local system if host is localhost."""
        if host in ("localhost", "127.0.0.1", "::1"):
            for cmd in (["iptables", "-S"], ["nft", "list", "ruleset"]):
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if r.returncode == 0 and r.stdout.strip():
                        return r.stdout
                except Exception:
                    pass
        return None

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        if not args.strip():
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        rules_text = args.strip()

        # If single word / IP, try live grab
        if " " not in rules_text and "\n" not in rules_text:
            live = self._get_live_rules(rules_text)
            if live:
                rules_text = live
            else:
                # Port scan to infer rules
                return SkillResult(self.name, True,
                    f"**Firewall Auditor**\n\n"
                    f"  To audit rules: paste iptables -S output directly.\n"
                    f"  For {rules_text}: use `/skill port_scanner {rules_text} 1-1024` to infer open ports,\n"
                    f"  then paste those results here for rule inference.",
                    False, [])

        lines    = ["**Firewall Rules Audit**\n"]
        findings : list[tuple[str, str]] = []  # (severity, description)

        rule_lines = rules_text.strip().splitlines()
        lines.append(f"  Total rules parsed: {len(rule_lines)}")

        # Check each dangerous pattern
        for pattern, severity, description in self.DANGER_PATTERNS:
            matching = [l for l in rule_lines if pattern.search(l)]
            if matching:
                findings.append((severity, f"{description} — {matching[0][:80]}"))

        # Egress filtering check
        egress_rules = [l for l in rule_lines if "OUTPUT" in l and "DROP" in l]
        if not egress_rules:
            findings.append(("medium", "No egress (OUTPUT) DROP rules found — unrestricted outbound"))

        # Count ACCEPT vs DROP
        accepts = sum(1 for l in rule_lines if "-j ACCEPT" in l or "accept" in l.lower())
        drops   = sum(1 for l in rule_lines if "-j DROP" in l or "-j REJECT" in l or "drop" in l.lower())
        lines.extend([
            f"  ACCEPT rules    : {accepts}",
            f"  DROP/REJECT     : {drops}",
        ])

        risk = "critical" if any(s == "critical" for s, _ in findings) else \
               "high"     if any(s == "high"     for s, _ in findings) else \
               "medium"   if findings else "low"

        lines.extend([
            "",
            f"  **Risk Level : [{risk.upper()}]**",
            "",
            "  **Findings:**" if findings else "  ✓ No obvious over-permissive rules detected",
        ])
        for sev, desc in findings:
            lines.append(f"    [{sev.upper():<8}] {desc}")

        out  = "\n".join(lines)
        tags = ["firewall_audit"]
        if risk in ("critical","high"): tags.append("overpermissive_firewall")
        return SkillResult(self.name, True, out, True, tags)


class ContainerScannerSkill(Skill):
    """
    Container security scan: Dockerfile analysis, image inspection, secret detection.
    Maps to UI tool: container-scan
    Real functionality: docker inspect, image manifest, Dockerfile linting.
    """
    name             = "container_scanner"
    description      = "Container security: Docker image inspect, Dockerfile audit, secret scan, privilege check"
    usage            = "container_scanner <image:tag OR Dockerfile_path>"
    trigger_patterns = ["container scan", "docker scan", "image scan", "container security", "dockerfile"]

    SECRET_PATTERNS = [
        (re.compile(r'(?i)(password|passwd|secret|api_key|token)\s*[=:]\s*["\']?[^\s"\']{8,}'), "secret"),
        (re.compile(r'(?i)AWS_ACCESS_KEY_ID'),                                                   "aws_key"),
        (re.compile(r'(?i)PRIVATE_KEY'),                                                         "private_key"),
        (re.compile(r'(?i)(GITHUB_TOKEN|GH_TOKEN)'),                                             "github_token"),
    ]
    DOCKERFILE_RISKS = [
        (re.compile(r'^FROM\s+.*:latest', re.M | re.I),  "medium",   "Using :latest tag (unpinned)"),
        (re.compile(r'^USER\s+root',      re.M | re.I),  "critical", "Running as root user"),
        (re.compile(r'^RUN\s+.*curl.+\|',re.M | re.I),  "high",     "Curl-pipe pattern (supply chain risk)"),
        (re.compile(r'ADD\s+http',        re.M | re.I),  "high",     "ADD from remote URL (no checksum)"),
        (re.compile(r'chmod\s+777',       re.M | re.I),  "high",     "chmod 777 — world-writable"),
        (re.compile(r'--privileged',      re.M | re.I),  "critical", "--privileged flag detected"),
    ]

    def _inspect_docker(self, image: str) -> dict | None:
        try:
            r = subprocess.run(
                ["docker", "inspect", image],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                return json.loads(r.stdout)[0]
        except Exception:
            pass
        return None

    def _scan_dockerfile(self, content: str) -> list[tuple[str, str]]:
        findings = []
        for pattern, severity, description in self.DOCKERFILE_RISKS:
            if pattern.search(content):
                findings.append((severity, description))
        # Secret scan
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                findings.append(("critical", f"Potential secret in Dockerfile: {secret_type}"))
        return findings

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        target = args.strip()
        if not target:
            return SkillResult(self.name, False, f"Usage: {self.usage}")

        lines    = [f"**Container Security Scan** `{target}`\n"]
        findings : list[tuple[str, str]] = []

        # Check if it's a Dockerfile path
        df_path = Path(target)
        if df_path.exists() and df_path.is_file():
            content = df_path.read_text(errors="replace")
            lines.append(f"  Source  : Dockerfile ({df_path})")
            lines.append(f"  Lines   : {len(content.splitlines())}")
            findings.extend(self._scan_dockerfile(content))

            # Show first FROM line
            from_line = next((l for l in content.splitlines() if l.strip().upper().startswith("FROM")), "")
            if from_line:
                lines.append(f"  Base    : {from_line.strip()}")

        else:
            # Try Docker inspect
            inspect = self._inspect_docker(target)
            if inspect:
                cfg    = inspect.get("Config", {})
                env    = cfg.get("Env", [])
                user   = cfg.get("User", "root")
                expose = list(inspect.get("Config", {}).get("ExposedPorts", {}).keys())
                host_cfg = inspect.get("HostConfig", {})
                privileged = host_cfg.get("Privileged", False)

                lines.extend([
                    f"  Image   : {target}",
                    f"  User    : {user or 'root (default)'}",
                    f"  Exposed : {', '.join(expose[:10]) if expose else 'none'}",
                ])
                if not user or user == "root":
                    findings.append(("critical", "Container runs as root"))
                if privileged:
                    findings.append(("critical", "--privileged mode enabled"))

                # Env var secret scan
                for e in env:
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        if pattern.search(e):
                            findings.append(("critical", f"Secret in ENV: {secret_type} ({e[:40]})"))

                # Common misconfigs
                if any("0.0.0.0" in str(p) for p in expose):
                    findings.append(("medium", "Ports bound to 0.0.0.0"))
            else:
                # No Docker available — CVE keyword scan via NVD on image name
                image_name = target.split(":")[0].split("/")[-1]
                lines.append(f"  Docker not available — performing CVE lookup for '{image_name}'")
                try:
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(image_name)}&resultsPerPage=5"
                    req = urllib.request.Request(url, headers={"User-Agent":"OMNIKON-SecOps/1.0.2"})
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data  = json.loads(resp.read())
                        vulns = data.get("vulnerabilities", [])
                        if vulns:
                            findings.append(("info", f"{len(vulns)} CVEs found for '{image_name}' in NVD"))
                            for v in vulns[:3]:
                                cid = v["cve"]["id"]
                                findings.append(("medium", f"NVD: {cid}"))
                except Exception:
                    lines.append("  NVD lookup failed — check connectivity")

        risk = "critical" if any(s == "critical" for s, _ in findings) else \
               "high"     if any(s == "high"     for s, _ in findings) else \
               "medium"   if findings else "low"

        lines.extend([
            "",
            f"  **Risk Level : [{risk.upper()}]**",
            "",
            "  **Findings:**" if findings else "  ✓ No critical container issues detected",
        ])
        for sev, desc in findings:
            lines.append(f"    [{sev.upper():<8}] {desc}")

        out  = "\n".join(lines)
        tags = ["container_scan", target[:40]]
        if risk == "critical": tags.append("critical_container")
        return SkillResult(self.name, True, out, True, tags)


class CloudPostureSkill(Skill):
    """
    Cloud security posture assessment via provider CLIs and public APIs.
    Maps to UI tool: cloud-posture
    Real functionality: AWS CLI checks, public S3 bucket detection, IAM analysis.
    """
    name             = "cloud_posture"
    description      = "Cloud security posture: AWS/GCP/Azure IAM, public buckets, security groups, logging"
    usage            = "cloud_posture <aws_account_id|gcp_project|azure_sub> [aws|gcp|azure]"
    trigger_patterns = ["cloud posture", "cloud security", "aws security", "s3 bucket", "iam review", "cloud audit"]

    def _aws_check(self, account: str) -> list[tuple[str, str]]:
        findings = []
        cli_cmds = [
            (["aws", "s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "json"],
             "s3_list"),
            (["aws", "iam", "generate-credential-report"], "iam_report"),
            (["aws", "cloudtrail", "describe-trails", "--output", "json"], "cloudtrail"),
            (["aws", "ec2", "describe-security-groups", "--output", "json"], "security_groups"),
        ]
        for cmd, check_type in cli_cmds:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if r.returncode != 0:
                    continue
                if check_type == "s3_list":
                    buckets = json.loads(r.stdout) if r.stdout.strip() else []
                    for bucket in buckets[:10]:
                        # Check public access
                        pub_r = subprocess.run(
                            ["aws","s3api","get-bucket-acl","--bucket",bucket,"--output","json"],
                            capture_output=True, text=True, timeout=10)
                        if "AllUsers" in pub_r.stdout or "AuthenticatedUsers" in pub_r.stdout:
                            findings.append(("critical", f"S3 bucket public: {bucket}"))
                elif check_type == "cloudtrail":
                    trails = json.loads(r.stdout).get("trailList", [])
                    if not trails:
                        findings.append(("high", "CloudTrail: no trails configured"))
                    else:
                        for t in trails:
                            if not t.get("IsMultiRegionTrail"):
                                findings.append(("medium", f"CloudTrail '{t.get('Name')}' not multi-region"))
                elif check_type == "security_groups":
                    sgs = json.loads(r.stdout).get("SecurityGroups", [])
                    for sg in sgs:
                        for perm in sg.get("IpPermissions", []):
                            for rng in perm.get("IpRanges", []):
                                if rng.get("CidrIp") == "0.0.0.0/0":
                                    port = perm.get("FromPort","all")
                                    sev  = "critical" if port in (22,3389) else "high"
                                    findings.append((sev, f"SG {sg.get('GroupId')}: port {port} open to 0.0.0.0/0"))
            except FileNotFoundError:
                findings.append(("info", f"AWS CLI not installed — install with: pip install awscli"))
                break
            except Exception as e:
                findings.append(("info", f"AWS check {check_type} failed: {str(e)[:60]}"))
        return findings

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        parts    = args.strip().split()
        if not parts:
            return SkillResult(self.name, False, f"Usage: {self.usage}")
        target   = parts[0]
        provider = (parts[1].lower() if len(parts) > 1 else "aws")

        lines    = [f"**Cloud Security Posture** `{target}` ({provider.upper()})\n"]
        findings : list[tuple[str, str]] = []

        if provider == "aws":
            findings.extend(self._aws_check(target))
            if not findings:
                # No CLI — do a public bucket name probe
                lines.append("  AWS CLI not available or no credentials — performing public probe\n")
                # Try common bucket naming patterns
                for suffix in ["", "-public", "-data", "-backup", "-dev", "-prod"]:
                    bucket_url = f"https://{target}{suffix}.s3.amazonaws.com/"
                    try:
                        req = urllib.request.Request(bucket_url,
                            headers={"User-Agent": "OMNIKON-SecOps/1.0.2"})
                        with urllib.request.urlopen(req, timeout=5) as r:
                            if r.status == 200:
                                findings.append(("critical", f"Public S3 bucket: {target}{suffix}"))
                    except urllib.error.HTTPError as e:
                        if e.code == 403:
                            lines.append(f"  Bucket {target}{suffix}: exists but access denied (403)")
                    except Exception:
                        pass
        else:
            lines.append(f"  Provider: {provider.upper()} — CLI checks require configured credentials")
            lines.append("  Install: aws-cli / gcloud / az CLI and configure credentials")
            findings.append(("info", f"Manual {provider.upper()} CLI checks required"))

        risk = "critical" if any(s == "critical" for s, _ in findings) else \
               "high"     if any(s == "high"     for s, _ in findings) else \
               "medium"   if any(s == "medium"   for s, _ in findings) else \
               "low"      if findings else "info"

        lines.extend([
            f"  **Risk Level : [{risk.upper()}]**",
            "",
            "  **Findings:**" if findings else "  ✓ No public exposures detected",
        ])
        for sev, desc in findings:
            lines.append(f"    [{sev.upper():<8}] {desc}")

        out  = "\n".join(lines)
        tags = ["cloud_posture", provider, target[:40]]
        if risk == "critical": tags.append("public_exposure")
        return SkillResult(self.name, True, out, True, tags)




class SkillRegistry:
    def __init__(self):
        self._s: dict[str, Skill] = {}
    def register(self, s: Skill): self._s[s.name] = s
    def get(self, n: str) -> Skill | None: return self._s.get(n)
    def all(self) -> list[Skill]: return list(self._s.values())
    def detect(self, text: str) -> Skill | None:
        low = text.lower()
        for s in self._s.values():
            for p in s.trigger_patterns:
                if p in low: return s
        return None
    def help_text(self) -> str:
        sections = {
            "NETWORK":    ["port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector",
                           "http_header_analyzer","network_recon","dns_security"],
            "THREAT":     ["cve_lookup","ip_reputation","hash_lookup","ioc_extractor"],
            "ANALYSIS":   ["log_analyzer","vulnerability_scorer","vulnerability_assessment",
                           "web_app_scanner","api_security_audit","firewall_auditor"],
            "CLOUD/CTR":  ["cloud_posture","container_scanner"],
            "AUTH":       ["password_audit"],
            "UTILITY":    ["summarizer","memory_writer"],
        }
        lines = ["**SecOps Skills v1.0.2 — 21 skills (all real functionality):**\n"]
        for section, names in sections.items():
            lines.append(f"  ── {section} ──")
            for n in names:
                s = self.get(n)
                if s:
                    lines.append(f"  `{s.name}` — {s.description}")
                    lines.append(f"    Usage: {s.usage}\n")
        return "\n".join(lines)


def _registry() -> SkillRegistry:
    r = SkillRegistry()
    for cls in [
        # NETWORK
        PortScannerSkill, DnsLookupSkill, WhoisLookupSkill,
        SslCertInspectorSkill, HttpHeaderAnalyzerSkill,
        NetworkReconSkill, DnsSecuritySkill,
        # THREAT
        CveLookupSkill, IpReputationSkill, HashLookupSkill, IocExtractorSkill,
        # ANALYSIS
        LogAnalyzerSkill, VulnerabilityScorerSkill,
        VulnerabilityAssessmentSkill, WebAppScannerSkill,
        ApiSecurityAuditSkill, FirewallAuditorSkill,
        # CLOUD / CONTAINER / AUTH
        CloudPostureSkill, ContainerScannerSkill, PasswordAuditSkill,
        # UTILITY
        SummarizerSkill, MemoryWriterSkill,
    ]:
        r.register(cls())
    return r


# ─────────────────────────────────────────────────────────────────────────────
# ReAct Engine
# ─────────────────────────────────────────────────────────────────────────────

_REACT_SYSTEM = """\
You are operating in ReAct (Reason + Act) mode.

Each response MUST follow ONE of these formats:

  Thought: <your reasoning>
  Action: <skill_name> <args>

  — OR —

  Thought: <final reasoning>
  Final Answer: <complete answer>

Available skills:
{skills}

Rules:
- ONE Thought + ONE Action OR ONE Thought + Final Answer per turn.
- Never fabricate Observations — wait for the real result.
- Check layer 2.5 (Reasoning Trace) in context to avoid repeating failed actions.
- Keep Thoughts to 1–3 sentences.
"""

_RE_THOUGHT = re.compile(r"Thought:\s*(.+?)(?=\nAction:|\nFinal Answer:|$)", re.S)
_RE_ACTION  = re.compile(r"Action:\s*(\w+)\s*(.*?)(?:\n|$)", re.S)
_RE_FINAL   = re.compile(r"Final Answer:\s*(.+)", re.S)

MAX_ITER = 10
MAX_ERRS = 3


class ReactEngine:
    def __init__(self, mm: MemoryManager, skills: SkillRegistry):
        self.mm = mm; self.skills = skills

    def _sys(self) -> str:
        base = self.mm.context_for_query(self.mm.react.goal, top_k=3)
        react = _REACT_SYSTEM.format(
            skills="\n".join(f"  {s.name}: {s.description}" for s in self.skills.all()))
        return f"{base}\n\n---\n\n{react}"

    def _parse(self, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        if m := _RE_THOUGHT.search(text): out["thought"] = m.group(1).strip()
        if m := _RE_ACTION.search(text):
            out["action"] = m.group(1).strip(); out["action_args"] = m.group(2).strip()
        if m := _RE_FINAL.search(text):   out["final"] = m.group(1).strip()
        return out

    def _exec_skill(self, name: str, args: str) -> tuple[str, bool]:
        skill = self.skills.get(name)
        if not skill:
            avail = ", ".join(s.name for s in self.skills.all())
            return f"Unknown skill '{name}'. Available: {avail}", True
        try:
            r = skill.run(args, self.mm)
            if r.store_to_archive and r.success:
                self.mm.archive.store(f"[{r.skill}] {r.output[:500]}",
                                      source=f"skill_{r.skill}", tags=r.archive_tags)
            return r.output, not r.success
        except Exception as e:
            return f"Skill error: {e}", True

    def run(self, goal: str) -> str:
        self.mm.enable_react(goal)
        rm = self.mm.react; errs = 0
        print(f"\n🔄 ReAct: {goal}\n{'─'*60}")
        for i in range(1, MAX_ITER + 1):
            t0  = time.time()
            raw = call_deepseek(self._sys(), self.mm.working.build_messages(), temperature=0.3)
            lat = int((time.time()-t0)*1000)
            p   = self._parse(raw)
            thought = p.get("thought", raw[:200])
            rm.record(TraceType.THOUGHT, thought, latency_ms=lat)
            print(f"  💭 [{i}] {thought[:100]}")
            if "final" in p:
                ans = p["final"]
                rm.record(TraceType.FINAL, ans)
                self.mm.add_assistant_message(ans)
                self.mm.finish_react(ans)
                print(f"  ✅ Final: {ans[:160]}\n{'─'*60}")
                return ans
            act  = p.get("action", ""); aarg = p.get("action_args", "")
            if not act:
                rm.record(TraceType.OBSERVATION, "No Action in response.", is_error=True)
                self.mm.add_message("user", "No Action found. Respond: Thought: ... then Action: <skill> <args>")
                errs += 1
            else:
                rm.record(TraceType.ACTION, f"{act} {aarg}", tool_name=act)
                print(f"  ⚡ [{i}] Action: {act} {aarg[:70]}")
                t0 = time.time()
                obs, is_err = self._exec_skill(act, aarg)
                rm.record(TraceType.OBSERVATION, obs, is_error=is_err, latency_ms=int((time.time()-t0)*1000))
                print(f"  👁 [{i}] {obs[:100]}")
                if is_err: errs += 1
                self.mm.add_message("user", f"Observation: {obs}")
                self.mm.add_assistant_message(raw)
            if errs >= MAX_ERRS: print("  ⚠ Max errors reached."); break
        fallback = f"Loop ended after {i} iterations. Last: {rm.last_observation()[:200]}"
        self.mm.finish_react(fallback)
        return fallback

    def step(self, goal: str) -> tuple[str, bool]:
        rm = self.mm.react
        if not rm.enabled: self.mm.enable_react(goal)
        t0  = time.time()
        raw = call_deepseek(self._sys(), self.mm.working.build_messages(), temperature=0.3)
        lat = int((time.time()-t0)*1000)
        p   = self._parse(raw)
        thought = p.get("thought", raw[:200])
        rm.record(TraceType.THOUGHT, thought, latency_ms=lat)
        if "final" in p:
            ans = p["final"]
            rm.record(TraceType.FINAL, ans)
            self.mm.add_assistant_message(ans)
            self.mm.finish_react(ans)
            return f"✅ **Final Answer:**\n{ans}", True
        act = p.get("action",""); aarg = p.get("action_args","")
        if not act:
            rm.record(TraceType.OBSERVATION, "No Action produced.", is_error=True)
            return f"💭 **Thought:** {thought}\n\n⚠ No Action produced.", False
        rm.record(TraceType.ACTION, f"{act} {aarg}", tool_name=act)
        obs, is_err = self._exec_skill(act, aarg)
        rm.record(TraceType.OBSERVATION, obs, is_error=is_err)
        self.mm.add_message("user", f"Observation: {obs}")
        self.mm.add_assistant_message(raw)
        return (f"💭 **Thought:** {thought}\n\n"
                f"⚡ **Action:** `{act}` {aarg[:80]}\n\n"
                f"👁 **Observation:** {obs[:300]}"), False


# ─────────────────────────────────────────────────────────────────────────────
# Agent
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║     OMNIKON SEC·OPS  —  AI Agent  v1.0.2  (Python)             ║
║  LLM    : DeepSeek deepseek-chat                               ║
║  Skills : 21 real SecOps skills — UI-aligned, no mocks         ║
║  Memory : Layers 2.1–2.5 + JSONL Archive + ReAct               ║
║──────────────────────────────────────────────────────────────── ║
║  Network  : port_scanner dns_lookup whois_lookup               ║
║             ssl_cert_inspector http_header_analyzer            ║
║             network_recon dns_security                         ║
║  Threat   : cve_lookup ip_reputation hash_lookup ioc_extractor ║
║  Analysis : log_analyzer vulnerability_scorer                  ║
║             vulnerability_assessment web_app_scanner           ║
║             api_security_audit firewall_auditor                ║
║  Cloud    : cloud_posture container_scanner                    ║
║  Auth     : password_audit                                     ║
║  Utility  : summarizer memory_writer                           ║
║──────────────────────────────────────────────────────────────── ║
║  /skills  /skill <name> <args>    /react <goal>                 ║
║  /react-step  /react-status  /react-finish                      ║
║  /task  /step  /finish  /status  /archive  /recall  /quit       ║
╚══════════════════════════════════════════════════════════════════╝
"""

OPTIONAL_KEYS = """
Optional API keys for enhanced functionality:
  ABUSEIPDB_API_KEY    → live IP reputation scoring (ip_reputation skill)
  VIRUSTOTAL_API_KEY   → live hash/file malware lookup (hash_lookup skill)
"""


class Agent:
    def __init__(self, archive_path: str | Path = "agent_memory.jsonl"):
        self.mm     = MemoryManager(archive_path)
        self.skills = _registry()
        self.react  = ReactEngine(self.mm, self.skills)
        self._persona(); self._rules(); self._seed()
        logger.info("Agent v1.0.2 ready | %s | %d skills", archive_path, len(self.skills.all()))

    def _persona(self):
        c = self.mm.character
        c.name = "OMNIKON SEC·OPS"; c.tone = "precise and analytical"
        c.expertise = ["cybersecurity","network security","threat intelligence",
                       "vulnerability assessment","incident response","ReAct reasoning"]
        c.personality = (
            "Methodical. Evidence-first. Uses real tool output before drawing conclusions. "
            "Proactively chains skills for deep investigation."
        )
        c.response_format = "Markdown"
        c.constraints = [
            "Never reveal API keys or credentials.",
            "[CRITICAL] prefix mandatory for CVSS ≥7.0 or confirmed attacks.",
            "Always show actual skill output, never paraphrase tool results.",
            "In ReAct: always complete Thought → Action → Observation cycle.",
        ]

    def _rules(self):
        names = ", ".join(s.name for s in self.skills.all())
        self.mm.add_system_rule("Respond only in English.")
        self.mm.add_system_rule(f"SecOps skills ({len(self.skills.all())}): {names}")
        self.mm.add_system_rule(
            "Skill chaining examples:\n"
            "  Full recon   : dns_lookup → port_scanner → ssl_cert_inspector → http_header_analyzer\n"
            "  Vuln workflow: vulnerability_assessment → cve_lookup → vulnerability_scorer\n"
            "  Web audit    : web_app_scanner → api_security_audit → http_header_analyzer\n"
            "  Cloud audit  : cloud_posture → container_scanner\n"
            "  Threat hunt  : ioc_extractor → ip_reputation → hash_lookup"
        )

    def _seed(self):
        if len(self.mm.archive) > 0: return
        for c, s, t in [
            ("CVE-2024-1234: SQL injection AuthService v2.1. CVSS 9.8. Patch: v2.2+.", "knowledge_base", ["cve"]),
            ("Brute-force: 5+ failures single IP <10 min → rate-limit + SOC alert.", "playbook", ["brute-force"]),
            ("Incident 2024-03: Public S3 exposed PII. Fix: bucket policies + CloudTrail.", "incident_report", ["aws","s3"]),
            ("OWASP Top 10 2021: A01 Broken Access, A02 Crypto Failures, A03 Injection.", "knowledge_base", ["owasp"]),
            ("Security header baseline: HSTS, CSP, X-Frame-Options, X-Content-Type-Options required.", "playbook", ["headers"]),
        ]:
            self.mm.archive.store(c, source=s, tags=t)

    def _exec_skill(self, args: str) -> str:
        name, _, sargs = args.strip().partition(" ")
        s = self.skills.get(name.strip())
        if not s: return f"⚠ Unknown skill '{name}'. Try /skills"
        r = s.run(sargs, self.mm)
        if r.store_to_archive and r.success:
            self.mm.archive.store(f"[{r.skill}] {r.output[:500]}",
                                  source=f"skill_{r.skill}", tags=r.archive_tags)
        return r.output

    def chat(self, inp: str) -> str:
        s = inp.strip()
        if not s: return ""
        if s.startswith("/"):
            cmd, _, args = s[1:].partition(" ")
            cmd = cmd.lower()
            if cmd in ("quit","exit","q"): raise KeyboardInterrupt
            if cmd == "skills":       return self.skills.help_text()
            if cmd == "skill":        return self._exec_skill(args)
            if cmd == "react":
                if not args.strip(): return "Usage: /react <goal>"
                return self.react.run(args.strip())
            if cmd == "react-step":
                goal = args.strip() or self.mm.react.goal or "Investigate"
                out, done = self.react.step(goal)
                return out + ("\n\n_(done — /react-finish to archive)_" if done else "\n\n_(run /react-step again)_")
            if cmd == "react-status":
                rm = self.mm.react
                if not rm.enabled: return "ℹ ReAct not active."
                d = rm.snapshot_dict()
                lines = ["```",
                         f"Goal: {d['goal']}  Iters: {d['total_iterations']}  "
                         f"Tools: {d['total_tool_calls']}  Errors: {d['total_errors']}  Elapsed: {d['elapsed_s']}s",
                         "```", "**Last 6 steps:**"]
                lines += ["  " + t.short() for t in rm.traces()[-6:]]
                return "\n".join(lines)
            if cmd == "react-finish":
                e = self.mm.finish_react(args.strip())
                return "✓ ReAct closed." + (f" Archived → `{e.id}`" if e else "")
            if cmd == "task":
                parts = args.split("|"); obj = parts[0].strip()
                if not obj: return "Usage: /task <objective> [| step1 | ...]"
                steps = [p.strip() for p in parts[1:] if p.strip()]
                self.mm.start_task(obj, steps or None)
                return f"✓ Task: **{obj}**"
            if cmd == "step":
                try:
                    self.mm.complete_step(args.strip() or None)
                    st = self.mm.status
                    return f"✓ Step {st.current_step}/{st.total_steps} | Next: {', '.join(st.pending) or 'none'}"
                except RuntimeError as e: return f"⚠ {e}"
            if cmd == "finish":
                try:
                    e = self.mm.finish_task(args.strip() or None)
                    return f"✓ Archived → `{e.id}`"
                except RuntimeError as e: return f"⚠ {e}"
            if cmd == "status":
                snap = self.mm.snapshot(); ts = snap["task_status"]
                react_line = ("ON — " + snap["reasoning"]["goal"] if snap.get("react_enabled") and snap.get("reasoning") else "OFF")
                return (f"```\nCharacter : {snap['character_name']}\nLLM       : {DEEPSEEK_MODEL}\n"
                        f"Skills    : {len(self.skills.all())}\n"
                        f"Task      : {ts['objective'] or '(none)'} ({ts['progress_pct']}%)\n"
                        f"Archive   : {snap['archive_total']} entries\nTokens≈   : {snap['estimated_tokens']}\n"
                        f"ReAct     : {react_line}\n```")
            if cmd == "archive":
                if not args.strip(): return "Usage: /archive <text>"
                return f"✓ Stored → `{self.mm.archive.store(args.strip(), 'manual').id}`"
            if cmd == "recall":
                if not args.strip(): return "Usage: /recall <query>"
                hits = self.mm.archive.retrieve(args.strip(), top_k=5)
                if not hits: return "No memories found."
                return "**Recall:**\n" + "\n".join(f"{i+1}. [{h.source}] {h.content[:120]}…" for i, h in enumerate(hits))
            return f"Unknown command: /{cmd}"

        if (hint := self.skills.detect(s)):
            self.mm.add_task_content(f"[Skill hint: {hint.name} — try /skill {hint.name} or /react]")
        self.mm.add_user_message(s)
        reply = call_deepseek(self.mm.context_for_query(s, top_k=3), self.mm.working.build_messages())
        self.mm.add_assistant_message(reply)
        return reply


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--archive", default=os.getenv("ARCHIVE_PATH", "agent_memory.jsonl"))
    args = p.parse_args()
    print(BANNER)
    print(OPTIONAL_KEYS)
    agent = Agent(args.archive)
    print(f"  Archive: {args.archive} ({len(agent.mm.archive)} entries)")
    print(f"  Skills : {len(agent.skills.all())}\n")
    signal.signal(signal.SIGINT, lambda *_: (print("\nGoodbye."), sys.exit(0)))
    while True:
        try:
            line = input("You > ").strip()
        except EOFError:
            break
        if not line: continue
        try:
            r = agent.chat(line)
            if r: print(f"\nAgent >\n{r}\n")
        except KeyboardInterrupt:
            print("\nGoodbye."); break
        except Exception as e:
            logger.error("%s", e, exc_info=True); print(f"\n⚠ {e}\n")


if __name__ == "__main__":
    main()
