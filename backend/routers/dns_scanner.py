"""
routers/dns_scanner.py

Tool 1 — Domain & Subdomain Scanner
Per-subdomain columns: subdomain · ip_addresses · is_active · status_code · first_seen
No per-subdomain port scanning — fast, handles any domain in under 180 seconds.
ScanState pattern — partial results returned even on hard timeout.

Four subdomain sources (launched AFTER Phase 2 to avoid DNS resolver overload):
  1. CertSpotter        (CT — paginated up to 5 pages, with ConnectError retry)
  2. HackerTarget       (hostsearch API, with ConnectError retry)
  3. AlienVault OTX     (passive DNS — requires free OTX_API_KEY in .env)
  4. DNS brute-force    (guaranteed baseline, ~1500 candidates, fast batches)
"""

from __future__ import annotations

import asyncio
import ssl
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import os
import tempfile

import dns.resolver
import dns.exception
import httpx
import whois
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse

from utils.helpers import (
    extract_domain, get_random_ua, resolve_ip, safe_jsonable, COMMON_HEADERS
)

router = APIRouter()

COMMON_PORTS: list[tuple[int, str]] = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
    (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (8888, "Jupyter"),
    (27017, "MongoDB"), (9200, "Elasticsearch"), (5000, "Dev-Server"),
]

_MAX_PROBE_SUBDOMAINS = 2000
_SCAN_BUDGET          = 210
_PROBE_BATCH_SIZE     = 50

_port_semaphore: asyncio.Semaphore | None = None

# ─── Common subdomain prefixes for DNS brute-force ────────────────────────────
# Base hand-curated list (~740 entries) + programmatically-generated numbered/
# region/env combos (~800 entries) appended at module load time below.
_BRUTE_PREFIXES: list[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "admin", "blog", "shop", "store", "dev", "staging", "test", "api", "app",
    "cdn", "cloud", "git", "gitlab", "jenkins", "jira", "wiki", "vpn", "remote",
    "owa", "exchange", "autodiscover", "cpanel", "portal", "secure", "login",
    "sso", "auth", "accounts", "my", "panel", "dashboard", "monitor", "status",
    "docs", "support", "help", "forum", "community", "www2", "www3", "m",
    "mobile", "beta", "demo", "sandbox", "preview", "stg", "uat", "qa", "prod",
    "web", "web1", "web2", "app1", "app2", "server", "server1", "server2",
    "db", "db1", "database", "sql", "mysql", "redis", "cache", "search",
    "proxy", "gateway", "dns", "dns1", "dns2", "ns", "mx", "mx1", "mx2",
    "relay", "smtp2", "imap", "pop3", "email", "newsletter", "calendar",
    "drive", "files", "storage", "backup", "archive", "old", "new", "static",
    "assets", "img", "images", "media", "video", "content", "upload", "download",
    "public", "internal", "intranet", "corp", "office", "hr", "crm", "erp",
    "analytics", "data", "devops", "ci", "build", "deploy", "infra", "network",
    "security", "soc", "noc", "labs", "research", "eng", "ops",
    "pay", "billing", "invoice", "payments", "checkout", "cart", "orders",
    "tracking", "shipping", "booking", "news", "press", "events", "jobs",
    "careers", "about", "contact", "info", "legal", "privacy", "terms",
    "stage", "preprod", "development", "testing", "alpha", "canary", "edge",
    "origin", "direct", "lb", "load", "worker", "queue", "broker", "mq",
    "grafana", "prometheus", "kibana", "elastic", "logstash", "sentry",
    "vault", "consul", "k8s", "kube", "docker", "registry",
    "s3", "bucket", "blob", "object", "minio",
    "chat", "slack", "teams", "meet", "zoom", "call",
    "waf", "fw", "firewall", "ids", "ips", "scan",
    "whm", "plesk", "ispconfig", "directadmin", "webdisk",
    "ns5", "ns6", "dns3", "mx3", "mail2", "mail3", "smtp3",
    "imap2", "pop3s", "imaps", "smtps", "submission",
    "ftp2", "sftp", "telnet", "rdp", "vnc",
    "db2", "db3", "postgres", "mongo", "couchdb", "cassandra",
    "memcached", "elasticsearch2", "solr", "sphinx",
    "api2", "api3", "rest", "graphql", "grpc", "soap",
    "oauth", "saml", "ldap", "radius", "kerberos",
    "www4", "web3", "web4", "app3", "app4", "srv", "srv1", "srv2",
    "host", "host1", "host2", "node", "node1", "node2",
    "cluster", "master", "slave", "replica", "primary", "secondary",
    "dev1", "dev2", "test1", "test2", "stage1", "stage2",
    "us", "eu", "ap", "uk", "de", "fr", "jp", "cn", "in", "au",
    "east", "west", "north", "south", "central",
    "img1", "img2", "img3", "static1", "static2", "cdn1", "cdn2",
    "media1", "media2", "assets1", "assets2",
    "wordpress", "wp", "joomla", "drupal", "magento",
    "confluence", "bitbucket", "bamboo", "sonarqube",
    "mattermost", "rocketchat", "nextcloud", "owncloud",
    "lb1", "lb2", "proxy1", "proxy2", "nat", "gw", "gw1", "gw2",
    "fw1", "fw2", "vpn1", "vpn2", "tunnel",
    "san", "nas", "nfs", "log", "logs", "logging", "syslog",
    "zabbix", "nagios", "icinga", "prtg", "datadog",
    "mx4", "mx5", "mail4", "mail5", "smtp4", "smtp5",
    "postfix", "sendmail", "dovecot", "roundcube",
    "spam", "antispam", "barracuda", "proofpoint",
    "time", "ntp", "snmp", "tftp", "dhcp",
    "update", "updates", "patch", "repo", "mirror",
    "ticket", "tickets", "helpdesk", "servicedesk", "itsm",
    "sip", "voip", "pbx", "asterisk",
    "server3", "server4", "server5", "host3", "host4", "host5",
    "node3", "node4", "node5", "db4", "db5",
    "ci1", "ci2", "cd1", "cd2", "runner", "agent", "worker1", "worker2",
    "pipeline", "automation", "ansible", "puppet", "chef", "salt",
    "terraform", "packer", "vagrant",
    "sso2", "auth2", "cas", "adfs", "okta", "keycloak",
    "iam", "identity", "directory", "dc", "dc1", "dc2",
    "pki", "ca", "crl", "ocsp", "cert", "certs",
    # ── Extended prefixes for higher coverage ──
    "accounts", "ad", "adm", "admin2", "admin3", "agency", "ai",
    "alert", "alerts", "amp", "api4", "api5", "apis",
    "appengine", "apps", "ars", "autodiscover2",
    "b", "b2b", "backend", "bak", "base", "bench", "bi", "big",
    "board", "box", "brand", "bridge", "bug", "bugs", "build2",
    "business", "buy", "cache1", "cache2", "catalog",
    "cfg", "cgi", "ci3", "clients", "cloud2", "cms",
    "code", "config", "connect", "console", "core",
    "cron", "crowd", "customer", "customers",
    "daemon", "data2", "debug", "delivery", "design",
    "desktop", "dev3", "devapi", "devices", "dist",
    "dl", "doc", "domain", "echo", "ecom", "edu",
    "email2", "embed", "eng2", "enterprise", "entry",
    "env", "erp2", "es", "event", "ext", "extern", "external",
    "f", "fast", "feed", "feedback", "file", "finance",
    "flag", "flow", "fonts", "forms", "found", "front",
    "ftp3", "g", "game", "games", "geo", "global",
    "go", "graph", "group", "groups", "guard", "h",
    "health", "home", "hook", "hooks", "hub",
    "i", "id", "idc", "image", "inbox", "index",
    "integration", "io", "iot", "irc", "it",
    "j", "job", "json", "jump", "key", "keys", "know",
    "knowledge", "l", "lab", "landing", "launch", "learn",
    "legacy", "lib", "library", "link", "links", "linux",
    "list", "live", "local", "locale", "location",
    "lyncdiscover", "m2", "mailer", "main", "manage",
    "manager", "map", "maps", "marketing", "matrix",
    "message", "messages", "meta", "metrics", "micro",
    "middleware", "ml", "mob", "monitoring", "msg",
    "mta", "n", "name", "net", "next", "nginx", "note", "notes",
    "notify", "ns7", "ns8", "o", "open", "openid",
    "operator", "order", "out", "outlook", "p",
    "packages", "page", "pages", "partner", "partners",
    "pci", "photo", "photos", "ping", "pixel",
    "pkg", "platform", "play", "poc", "point",
    "pool", "pop2", "post", "preview2", "print",
    "private", "project", "projects", "promo",
    "protect", "pub", "push", "r", "raw", "rc",
    "read", "redirect", "ref", "release", "report", "reports",
    "resolve", "resource", "resources", "root", "route",
    "rss", "run", "s", "s1", "s2", "s3", "safe",
    "sandbox2", "scheduler", "sdk", "sec", "send",
    "service", "services", "session", "share", "shared",
    "shell", "sign", "signup", "site", "sites",
    "sms", "socket", "source", "spec", "sql2",
    "ssl", "sslvpn", "stack", "staff", "stat", "stats",
    "stream", "sub", "svn", "sw", "sync",
    "sys", "system", "t", "tag", "task", "tasks",
    "tcp", "tech", "temp", "tenant", "test3", "test4",
    "theme", "token", "tool", "tools", "trace",
    "track", "translate", "trial", "trunk", "trust",
    "ts", "tv", "u", "udp", "ui", "unix",
    "up", "user", "users", "v", "v1", "v2", "v3",
    "vdi", "vendor", "verify", "version", "vip",
    "vm", "vm1", "vm2", "vps", "w", "w3",
    "web5", "webapi", "webapps", "webconf", "weblog",
    "webproxy", "webserver", "websocket", "wh", "wireless",
    "wms", "work", "ws", "ww", "x", "xml",
    "xmpp", "y", "z", "zero", "zone",
]

# ── Programmatically-generated numbered/region/env prefixes ──────────────────
def _generate_extra_prefixes() -> list[str]:
    """Generate ~800+ extra prefixes from numbered series, regions, and combos."""
    extras: set[str] = set()

    _numbered_roots = [
        "mail", "ns", "web", "app", "api", "db", "srv", "node", "host",
        "www", "cdn", "proxy", "lb", "gw", "vpn", "dns", "mx", "ftp",
        "smtp", "dev", "test", "stage", "prod",
    ]
    for root in _numbered_roots:
        for n in range(1, 31):
            extras.add(f"{root}{n:02d}")

    _regions = [
        "us", "eu", "ap", "uk", "de", "fr", "jp", "sg", "au", "ca",
        "br", "in", "za", "ae", "nl", "ie",
    ]
    for region in _regions:
        for suffix in ["api", "web", "app", "cdn"]:
            extras.add(f"{region}-{suffix}")
        extras.add(f"{region}1")
        extras.add(f"{region}2")

    extras.update([
        "api-v1", "api-v2", "api-v3", "apiv1", "apiv2", "v1-api",
        "v2-api", "rest-v1", "rest-v2", "graphql-v1",
        "dev-api", "staging-api", "test-api", "qa-api", "uat-api",
        "prod-api", "dev-app", "staging-app", "dev-admin", "staging-admin",
        "dev-portal",
        "api-gateway", "auth-service", "user-service", "payment-service",
        "notification-service", "search-service", "media-service",
    ])

    return sorted(extras)

_existing = set(_BRUTE_PREFIXES)
for _p in _generate_extra_prefixes():
    if _p not in _existing:
        _BRUTE_PREFIXES.append(_p)
        _existing.add(_p)
del _existing


def _get_port_semaphore() -> asyncio.Semaphore:
    global _port_semaphore
    if _port_semaphore is None:
        _port_semaphore = asyncio.Semaphore(10)
    return _port_semaphore


@dataclass
class ScanState:
    target_domain:        str
    subdomains_data:      list[dict] = field(default_factory=list)
    dns_records:          dict       = field(default_factory=dict)
    whois_info:           dict       = field(default_factory=dict)
    ssl_info:             dict       = field(default_factory=dict)
    open_ports:           list[dict] = field(default_factory=list)
    total_discovered:     int        = 0
    large_domain_partial: bool       = False
    timeout_partial:      bool       = False
    sources:              dict       = field(default_factory=dict)
    scan_duration:        float      = 0.0

    def build_payload(self) -> dict:
        probed   = [s for s in self.subdomains_data if s.get("is_active") is not None]
        active   = sum(1 for s in probed if s.get("is_active"))
        inactive = len(probed) - active
        payload: dict = {
            "target_domain":        self.target_domain,
            "subdomains_found":     self.total_discovered,
            "active_count":         active,
            "inactive_count":       inactive,
            "subdomains":           self.subdomains_data,
            "dns_records":          self.dns_records,
            "whois_info":           self.whois_info,
            "ssl_info":             self.ssl_info,
            "open_ports":           self.open_ports,
            "scan_duration":        self.scan_duration,
            "large_domain_partial": self.large_domain_partial,
            "timeout_partial":      self.timeout_partial,
            "sources":              self.sources,
        }
        return payload


# ─── Source 1: CertSpotter (paginated, with ConnectError retry) ───────────────

async def _get_subdomains_certspotter(domain: str) -> dict[str, str]:
    """
    CertSpotter CT — free with first_seen dates and pagination.
    Loops up to 5 pages using the 'after' cursor. Stops early on empty
    page, non-200 status (especially 429 rate-limit), or ConnectError.
    Includes a 1-second delay between pages to respect anonymous rate limits.
    """
    url = "https://api.certspotter.com/v1/issuances"
    seen: dict[str, str] = {}
    after_cursor: str | None = None

    for page_num in range(5):
        params = {
            "domain":             domain,
            "include_subdomains": "true",
            "expand":             "dns_names",
            "match_wildcards":    "true",
        }
        if after_cursor:
            params["after"] = after_cursor

        resp = None
        for attempt in range(2):
            try:
                print(f"  [certspotter] page={page_num} querying {domain}...")
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
                    verify=False,
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(
                        url, params=params,
                        headers={"User-Agent": get_random_ua()},
                    )
                print(f"  [certspotter] page={page_num} status={resp.status_code} "
                      f"size={len(resp.content)} bytes")
                break
            except httpx.ConnectError as exc:
                if attempt == 0:
                    print(f"  [certspotter] ConnectError (transient), retrying in 2s: {exc}")
                    await asyncio.sleep(2)
                    continue
                print(f"  [certspotter] ConnectError after retry: {exc}")
                resp = None
                break
            except Exception as exc:
                print(f"  [certspotter] ERROR: {type(exc).__name__}: {exc}")
                resp = None
                break

        if resp is None:
            break
        if resp.status_code == 429:
            print(f"  [certspotter] rate limited (429) on page {page_num}, stopping")
            break
        if resp.status_code != 200:
            break

        try:
            data = resp.json()
        except Exception:
            break
        if not data:
            break

        for entry in data:
            not_before = (entry.get("not_before", "") or "")[:10]
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if (name and "*" not in name
                        and name.endswith(f".{domain}")
                        and name != domain):
                    if name not in seen:
                        seen[name] = not_before
                    elif not_before and not_before < seen[name]:
                        seen[name] = not_before

        after_cursor = str(data[-1].get("id", ""))
        if not after_cursor:
            break

        if page_num < 4:
            await asyncio.sleep(1)

    print(f"  [certspotter] SUCCESS — {len(seen)} subdomains across pages")
    return seen


# ─── Source 2: HackerTarget (with ConnectError retry) ─────────────────────────

async def _get_subdomains_hackertarget(domain: str) -> dict[str, str]:
    """HackerTarget hostsearch — returns subdomain -> IP dict."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    result: dict[str, str] = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = None
            for attempt in range(2):
                try:
                    resp = await client.get(url, headers={"User-Agent": get_random_ua()})
                    break
                except httpx.ConnectError as exc:
                    if attempt == 0:
                        print(f"  [hackertarget] ConnectError (transient), retrying in 2s: {exc}")
                        await asyncio.sleep(2)
                        continue
                    print(f"  [hackertarget] ConnectError after retry: {exc}")
                    return result
            if resp is None:
                return result
            if resp.status_code != 200:
                return result
            text = resp.text.strip()
            if not text or text.startswith("error") or "API count" in text:
                return result
            for line in text.splitlines():
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    name = parts[0].strip().lower()
                    ip   = parts[1].strip()
                    if name and name.endswith(f".{domain}") and "*" not in name:
                        result[name] = ip
    except Exception:
        pass
    print(f"  [hackertarget] {len(result)} subdomains")
    return result


# ─── Source 3: AlienVault OTX Passive DNS ─────────────────────────────────────

async def _get_subdomains_otx(domain: str) -> dict[str, dict]:
    """
    AlienVault OTX passive DNS — free with registered API key.
    Returns dict[subdomain -> {"ip": str, "first_seen": str}].
    Skipped gracefully if OTX_API_KEY is not set.
    """
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key:
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            try:
                with open(env_path) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("OTX_API_KEY="):
                            api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                            break
            except Exception:
                pass

    if not api_key:
        print("  [otx] OTX_API_KEY not set — skipping.")
        return {}

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    result: dict[str, dict] = {}
    try:
        print(f"  [otx] querying passive DNS for {domain}...")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=45.0, write=5.0, pool=5.0),
            verify=False,
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                url,
                headers={"X-OTX-API-Key": api_key, "User-Agent": get_random_ua(),
                         "Accept": "application/json"},
            )
            print(f"  [otx] status={resp.status_code} size={len(resp.content)} bytes")
            if resp.status_code != 200:
                return {}
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                address  = entry.get("address", "").strip()
                first    = (entry.get("first", "") or "")[:10]
                rtype    = entry.get("record_type", "")
                if rtype not in ("A", "AAAA", ""):
                    continue
                if (hostname and hostname.endswith(f".{domain}")
                        and hostname != domain and "*" not in hostname):
                    if hostname not in result:
                        result[hostname] = {"ip": address, "first_seen": first}
                    elif first and first < result[hostname].get("first_seen", "9"):
                        result[hostname]["first_seen"] = first
    except httpx.ConnectError as exc:
        print(f"  [otx] ConnectError: {exc}")
        return {}
    except Exception as exc:
        print(f"  [otx] ERROR: {type(exc).__name__}: {exc}")
        return {}

    print(f"  [otx] SUCCESS — {len(result)} unique subdomains")
    return result


# ─── Source 4: DNS brute-force (fast batches of 150) ──────────────────────────

async def _get_subdomains_bruteforce(
    domain: str,
    known: set[str],
    budget_fn,
    min_budget: float = 8.0,
) -> dict[str, str]:
    """DNS brute-force using common prefixes. Returns subdomain -> IP."""
    candidates = [
        f"{p}.{domain}" for p in _BRUTE_PREFIXES
        if f"{p}.{domain}" not in known
    ]
    if not candidates:
        return {}

    print(f"  [bruteforce] {len(candidates)} candidates "
          f"(budget={budget_fn():.0f}s)")
    found: dict[str, str] = {}

    async def _try_resolve(name: str) -> tuple[str, str] | None:
        try:
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout  = 1.2
            resolver.lifetime = 1.2
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(name, "A"))
            ips = [rdata.address for rdata in answers]
            return (name, ips[0]) if ips else None
        except (asyncio.CancelledError, Exception):
            return None

    for i in range(0, len(candidates), 150):
        if budget_fn() < min_budget:
            print(f"  [bruteforce] budget exhausted at candidate {i}, stopping")
            break
        batch = candidates[i : i + 150]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *[_try_resolve(c) for c in batch],
                    return_exceptions=True,
                ),
                timeout=max(5, min(budget_fn() - 5, 15)),
            )
            for r in results:
                if isinstance(r, tuple) and r is not None:
                    found[r[0]] = r[1]
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

    print(f"  [bruteforce] {len(found)} new subdomains found")
    return found


# ─── DNS / WHOIS / SSL helpers ────────────────────────────────────────────────

def _query_dns(domain: str) -> dict[str, list[dict]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 8
    records: dict[str, list[dict]] = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        records[rtype] = []
        try:
            answers = resolver.resolve(domain, rtype)
            ttl = answers.rrset.ttl if answers.rrset else 0
            for rdata in answers:
                if rtype == "A":
                    records[rtype].append({"value": rdata.address, "ttl": ttl})
                elif rtype == "AAAA":
                    records[rtype].append({"value": rdata.address, "ttl": ttl})
                elif rtype == "MX":
                    records[rtype].append({
                        "value":    str(rdata.exchange).rstrip("."),
                        "priority": int(rdata.preference), "ttl": ttl})
                elif rtype == "NS":
                    records[rtype].append(
                        {"value": str(rdata.target).rstrip("."), "ttl": ttl})
                elif rtype == "TXT":
                    txt_val = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                    records[rtype].append(
                        {"value": txt_val.replace("\x00", "").strip(), "ttl": ttl})
                elif rtype == "CNAME":
                    records[rtype].append(
                        {"value": str(rdata.target).rstrip("."), "ttl": ttl})
                elif rtype == "SOA":
                    records[rtype].append({
                        "mname":   str(rdata.mname).rstrip("."),
                        "rname":   str(rdata.rname).rstrip("."),
                        "serial":  int(rdata.serial), "refresh": int(rdata.refresh),
                        "retry":   int(rdata.retry),  "expire":  int(rdata.expire),
                        "minimum": int(rdata.minimum), "ttl":    ttl})
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
    return records


def _get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        def _s(v, fallback="N/A"):
            if isinstance(v, list): v = v[0] if v else None
            if isinstance(v, datetime): return v.strftime("%Y-%m-%d")
            if v is None or (isinstance(v, str) and not v.strip()): return fallback
            return str(v)

        name_servers = w.name_servers or []
        if isinstance(name_servers, str): name_servers = [name_servers]
        ns_display = ", ".join(sorted(set(
            str(ns).lower().rstrip(".") for ns in name_servers
        ))) or "N/A"
        emails = w.emails or []
        if isinstance(emails, str): emails = [emails]
        return {
            "registrar":       _s(w.registrar),
            "creation_date":   _s(w.creation_date),
            "expiration_date": _s(w.expiration_date),
            "updated_date":    _s(w.updated_date),
            "name_servers":    ns_display,
            "status":          _s(w.status),
            "emails":          list(set(str(e) for e in emails)),
            "country":         _s(w.country),
            "org":             _s(w.org),
        }
    except Exception:
        return {}


def _parse_cert(cert: dict, domain: str) -> dict:
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    subject = dict(x[0] for x in cert.get("subject", []))
    san     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    issuer_org  = issuer.get("organizationName") or issuer.get("commonName", "Unknown")
    subject_org = subject.get("organizationName", "")
    is_self_signed = (
        issuer.get("commonName") == subject.get("commonName")
        and issuer_org == subject_org
    )
    return {
        "issuer":         issuer_org,
        "subject":        subject.get("commonName", domain),
        "not_before":     cert.get("notBefore"),
        "not_after":      cert.get("notAfter"),
        "is_self_signed": is_self_signed,
        "san":            san,
    }


def _get_ssl_info(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return {"is_valid": True, **_parse_cert(cert, domain), "error": None}

    except ssl.SSLCertVerificationError as exc:
        err_msg = str(exc)
        der = None
        try:
            ctx_nv = ssl.create_default_context()
            ctx_nv.check_hostname = False
            ctx_nv.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=6) as raw:
                with ctx_nv.wrap_socket(raw, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except Exception:
            pass

        cert_info: dict = {}
        if der:
            try:
                pem = ssl.DER_cert_to_PEM_cert(der)
                with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".pem", delete=False) as f:
                    f.write(pem)
                    tmppath = f.name
                try:
                    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx2.check_hostname = False
                    ctx2.verify_mode    = ssl.CERT_NONE
                    ctx2.load_verify_locations(tmppath)
                    with socket.create_connection((domain, 443), timeout=6) as raw:
                        ctx2.verify_mode = ssl.CERT_OPTIONAL
                        with ctx2.wrap_socket(raw, server_hostname=domain) as ssock:
                            cert_info = ssock.getpeercert() or {}
                finally:
                    os.unlink(tmppath)
            except Exception:
                pass

        if cert_info:
            return {"is_valid": True, **_parse_cert(cert_info, domain),
                    "error": f"Chain not fully verified locally: {err_msg}"}
        return {"is_valid": None, "issuer": "Unknown (verification failed)",
                "subject": domain, "not_before": None, "not_after": None,
                "is_self_signed": False, "san": [],
                "error": f"Certificate chain verification failed: {err_msg}"}

    except (ConnectionRefusedError, OSError):
        return {"is_valid": None, "error": "Port 443 not reachable",
                "is_self_signed": False, "san": []}
    except Exception as exc:
        return {"is_valid": None, "error": str(exc),
                "is_self_signed": False, "san": []}


async def _check_port(ip: str, port: int, service: str) -> dict:
    is_open = False
    async with _get_port_semaphore():
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.5)
            is_open = True
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
        except Exception:
            pass
    return {"port": port, "service": service, "is_open": is_open}


async def _port_scan(domain: str) -> list[dict]:
    ip = resolve_ip(domain)
    if not ip:
        return [{"port": p, "service": s, "is_open": False} for p, s in COMMON_PORTS]
    return list(await asyncio.gather(
        *[_check_port(ip, port, service) for port, service in COMMON_PORTS]
    ))


async def _resolve_subdomain(subdomain: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = 2
        resolver.lifetime = 2
        answers = await loop.run_in_executor(
            None, lambda: resolver.resolve(subdomain, "A"))
        ips = [rdata.address for rdata in answers]
    except Exception:
        ips = []
    return {"subdomain": subdomain, "ip_addresses": ips}


async def _probe_subdomain(subdomain: str, ip_addresses: list[str]) -> dict:
    if not ip_addresses:
        return {"is_active": False, "status_code": None}
    headers = {"User-Agent": get_random_ua(), **COMMON_HEADERS}
    async with httpx.AsyncClient(
            timeout=3.0, follow_redirects=True, verify=False) as client:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{subdomain}", headers=headers)
                return {"is_active": True, "status_code": resp.status_code}
            except Exception:
                continue
    return {"is_active": False, "status_code": None}


# ─── Core scan pipeline ───────────────────────────────────────────────────────

async def _run_scan(domain: str, start_time: float, state: ScanState) -> None:
    def _remaining() -> float:
        return _SCAN_BUDGET - (time.time() - start_time)

    print(f"\n{'='*60}")
    print(f"  SCAN STARTED: {domain}  (budget={_SCAN_BUDGET}s, "
          f"sources: certspotter(paginated) + HackerTarget + OTX + brute-force)")
    print(f"{'='*60}")

    # ── Phase 1: DNS / WHOIS / SSL FIRST (clears DNS resolver pressure) ───
    port_scan_task = asyncio.create_task(_port_scan(domain))
    print(f"  [phase1] DNS/WHOIS/SSL (elapsed={time.time()-start_time:.1f}s)")
    loop = asyncio.get_event_loop()
    dns_records, whois_info, ssl_info = await asyncio.gather(
        loop.run_in_executor(None, _query_dns,    domain),
        loop.run_in_executor(None, _get_whois,    domain),
        loop.run_in_executor(None, _get_ssl_info, domain),
    )
    state.dns_records = dns_records
    state.whois_info  = whois_info
    state.ssl_info    = ssl_info
    print(f"  [phase1] done (elapsed={time.time()-start_time:.1f}s, "
          f"remaining={_remaining():.0f}s)")

    # ── Phase 2: Fire API discovery tasks AFTER Phase 1 (DNS resolver free)
    certspotter_task  = asyncio.create_task(_get_subdomains_certspotter(domain))
    await asyncio.sleep(0.3)
    hackertarget_task = asyncio.create_task(_get_subdomains_hackertarget(domain))
    await asyncio.sleep(0.3)
    otx_task          = asyncio.create_task(_get_subdomains_otx(domain))

    # ── Phase 3: Collect discovery results ────────────────────────────────

    # 3a — CertSpotter (paginated)
    certspotter_timeout = min(45, max(5, _remaining() - 10))
    try:
        certspotter_result: dict[str, str] = await asyncio.wait_for(
            certspotter_task, timeout=certspotter_timeout)
    except Exception:
        certspotter_result = {}
    print(f"  [phase3] certspotter={len(certspotter_result)} subdomains "
          f"(elapsed={time.time()-start_time:.1f}s)")

    # 3b — HackerTarget
    ht_timeout = min(15, max(3, _remaining() - 5))
    try:
        ht_results: dict[str, str] = await asyncio.wait_for(
            hackertarget_task, timeout=ht_timeout)
    except Exception:
        ht_results = {}
    print(f"  [phase3] hackertarget={len(ht_results)} subdomains "
          f"(elapsed={time.time()-start_time:.1f}s)")

    # 3c — AlienVault OTX
    otx_timeout = min(50, max(10, _remaining() - 10))
    try:
        otx_result: dict[str, dict] = await asyncio.wait_for(
            otx_task, timeout=otx_timeout)
    except Exception:
        otx_result = {}
    print(f"  [phase3] otx={len(otx_result)} subdomains "
          f"(elapsed={time.time()-start_time:.1f}s)")

    # ── Build merged first_seen lookup ─────────────────────────────────────
    ct_first_seen: dict[str, str] = {}
    # OTX first_seen (lowest priority)
    for name, meta in otx_result.items():
        date = meta.get("first_seen", "")
        if date and (name not in ct_first_seen or date < ct_first_seen[name]):
            ct_first_seen[name] = date
    # CertSpotter (highest priority — most accurate CT dates)
    ct_first_seen.update(certspotter_result)

    # ── Build merged IP lookup ─────────────────────────────────────────────
    ip_lookup: dict[str, str] = {}
    for name, meta in otx_result.items():
        ip = meta.get("ip", "")
        if ip and name not in ip_lookup:
            ip_lookup[name] = ip
    ip_lookup.update(ht_results)  # HackerTarget overwrites (more current)

    # ── Phase 3d: DNS brute-force (fills remaining time budget) ───────────
    known_so_far = (
        set(ct_first_seen.keys())
        | set(ht_results.keys())
        | set(otx_result.keys())
    )
    brute_results: dict[str, str] = {}
    if _remaining() > 15:
        print(f"  [phase3d] DNS brute-force (remaining={_remaining():.0f}s)...")
        try:
            brute_results = await asyncio.wait_for(
                _get_subdomains_bruteforce(domain, known_so_far, _remaining),
                timeout=max(10, _remaining() - 12),
            )
        except asyncio.TimeoutError:
            print("  [phase3d] brute-force timed out")
        except Exception as exc:
            print(f"  [phase3d] brute-force error: {exc}")
    ip_lookup.update(brute_results)

    # ── Merge all unique names ─────────────────────────────────────────────
    all_names = sorted(
        set(ct_first_seen.keys())
        | set(ht_results.keys())
        | set(otx_result.keys())
        | set(brute_results.keys())
    )
    state.total_discovered = len(all_names)
    state.sources = {
        "certspotter":  len(certspotter_result),
        "hackertarget": len(ht_results),
        "otx":          len(otx_result),
        "bruteforce":   len(brute_results),
    }
    print(f"  [merge] {len(all_names)} unique subdomains total — "
          f"certspotter={len(certspotter_result)}, "
          f"ht={len(ht_results)}, otx={len(otx_result)}, "
          f"brute={len(brute_results)}")

    # ── Phase 4: Batch HTTP probe ──────────────────────────────────────────
    to_probe     = all_names[:_MAX_PROBE_SUBDOMAINS]
    overflow     = all_names[_MAX_PROBE_SUBDOMAINS:]
    timed_out    = False
    probed_up_to = 0

    print(f"  [phase4] probing {len(to_probe)} subdomains "
          f"(remaining={_remaining():.0f}s)")

    for i in range(0, len(to_probe), _PROBE_BATCH_SIZE):
        if _remaining() < 8:
            timed_out = True
            print(f"  [phase4] budget exhausted, stopping at {i}")
            break

        batch        = to_probe[i : i + _PROBE_BATCH_SIZE]
        probed_up_to = i + len(batch)

        resolved_batch: list[dict] = []
        needs_dns: list[str]       = []
        for s in batch:
            if s in ip_lookup and ip_lookup[s]:
                resolved_batch.append(
                    {"subdomain": s, "ip_addresses": [ip_lookup[s]]})
            else:
                needs_dns.append(s)

        if needs_dns:
            try:
                dns_resolved = await asyncio.wait_for(
                    asyncio.gather(*[_resolve_subdomain(s) for s in needs_dns]),
                    timeout=max(3, _remaining() - 5))
                resolved_batch.extend(dns_resolved)
            except asyncio.TimeoutError:
                for s in needs_dns:
                    resolved_batch.append({"subdomain": s, "ip_addresses": []})

        order_map = {s: idx for idx, s in enumerate(batch)}
        resolved_batch.sort(key=lambda r: order_map.get(r["subdomain"], 999))

        if _remaining() > 6:
            try:
                probed_batch = await asyncio.wait_for(
                    asyncio.gather(*[
                        _probe_subdomain(r["subdomain"], r["ip_addresses"])
                        for r in resolved_batch]),
                    timeout=max(5, _remaining() - 4))
            except asyncio.TimeoutError:
                probed_batch = ([{"is_active": None, "status_code": None}]
                                * len(resolved_batch))
        else:
            probed_batch = ([{"is_active": None, "status_code": None}]
                            * len(resolved_batch))

        for resolved, probed in zip(resolved_batch, probed_batch):
            name = resolved["subdomain"]
            state.subdomains_data.append({
                "subdomain":    name,
                "ip_addresses": resolved["ip_addresses"],
                "is_active":    probed["is_active"],
                "status_code":  probed["status_code"],
                "first_seen":   ct_first_seen.get(name, "—") or "—",
            })

    state.timeout_partial      = timed_out
    state.large_domain_partial = timed_out or len(overflow) > 0

    unprobed: list[str] = []
    if timed_out:
        unprobed.extend(to_probe[probed_up_to:])
    unprobed.extend(overflow)

    for name in unprobed:
        ip = ip_lookup.get(name, "")
        state.subdomains_data.append({
            "subdomain":    name,
            "ip_addresses": [ip] if ip else [],
            "is_active":    None,
            "status_code":  None,
            "first_seen":   ct_first_seen.get(name, "—") or "—",
        })

    # ── Phase 5: Main domain port scan ────────────────────────────────────
    if _remaining() > 2:
        try:
            state.open_ports = await asyncio.wait_for(
                port_scan_task, timeout=max(2, _remaining() - 1))
        except (asyncio.TimeoutError, Exception):
            port_scan_task.cancel()
            state.open_ports = []
    else:
        port_scan_task.cancel()
        state.open_ports = []

    state.scan_duration = round(time.time() - start_time, 2)
    print(f"  [DONE] {state.scan_duration}s — "
          f"{len(state.subdomains_data)} subdomains returned")
    print(f"{'='*60}\n")


# ─── Route ────────────────────────────────────────────────────────────────────

@router.post("/dns-scan")
async def dns_scan(
    target_url: str = Query(..., description="Target domain or full URL to scan"),
):
    """
    Full OSINT Domain & Subdomain Scanner.
    Four parallel sources: CertSpotter(paginated) + HackerTarget + OTX + DNS brute-force.
    Per-subdomain: subdomain | ip | is_active | status_code | first_seen
    Also: DNS records, WHOIS, TLS/SSL, main domain port scan.
    """
    start_time = time.time()
    domain = extract_domain(target_url)
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain or URL.")

    state = ScanState(target_domain=domain)

    try:
        await asyncio.wait_for(
            _run_scan(domain, start_time, state),
            timeout=_SCAN_BUDGET + 15,
        )
        if not state.scan_duration:
            state.scan_duration = round(time.time() - start_time, 2)

        payload    = state.build_payload()
        is_partial = payload.get("timeout_partial", False)
        subs       = payload["subdomains_found"]
        dur        = payload["scan_duration"]

        msg = (
            f"DNS scan {'partially ' if is_partial else ''}completed for "
            f"{domain} — {subs} subdomains in {dur}s"
        )
        if is_partial:
            msg += " (some not probed — First Seen still shown)"

        return JSONResponse(content={"success": True, "message": msg,
                                     "data": safe_jsonable(payload)})

    except asyncio.TimeoutError:
        state.scan_duration        = round(time.time() - start_time, 2)
        state.timeout_partial      = True
        state.large_domain_partial = True

        for getter, attr in [(_query_dns,    "dns_records"),
                              (_get_whois,   "whois_info"),
                              (_get_ssl_info,"ssl_info")]:
            if not getattr(state, attr):
                try:
                    result = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, getter, domain),
                        timeout=3.0)
                    setattr(state, attr, result)
                except Exception:
                    pass

        payload = state.build_payload()
        return JSONResponse(content={
            "success": True,
            "message": (f"DNS scan partially completed for {domain} in "
                        f"{payload['scan_duration']}s (hard timeout)"),
            "data": safe_jsonable(payload)})

    except Exception as exc:
        state.scan_duration   = round(time.time() - start_time, 2)
        state.timeout_partial = True
        payload = state.build_payload()
        payload["error_detail"] = str(exc)
        return JSONResponse(content={
            "success": True,
            "message": (f"DNS scan partially completed for {domain} — "
                        f"partial results returned"),
            "data": safe_jsonable(payload)})