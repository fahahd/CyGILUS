"""
routers/phishing_detector.py
CyGILUS Tool 4 — Phishing Site Detector
POST /api/tools/phishing-detect?target_url=<url>

Runs 10 OSINT feature extractors concurrently, feeds into an XGBoost model,
provides SHAP explanations, and discovers similar suspicious domains.
"""

import os
import ssl
import time
import socket
import asyncio
from datetime import datetime

import httpx
import whois
from dns import resolver as dns_resolver
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from utils.helpers import extract_domain, get_random_ua

# ─── Load environment variables ──────────────────────────────────────────────

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── Import model ────────────────────────────────────────────────────────────

from utils.phishing_model import predict, build_osint_display

# ─── Router ──────────────────────────────────────────────────────────────────

router = APIRouter()

# ─── Constants ───────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "account", "banking",
    "payment", "paypal", "ebay", "amazon", "apple", "microsoft",
    "google", "support", "service", "confirm", "password", "signin",
    "sign-in", "auth", "wallet", "crypto", "token", "recover",
    "unlock", "suspended", "alert", "notice", "warning", "urgent",
    "limited", "action", "required", "validate", "reactivate",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".link", ".buzz", ".win", ".racing",
    ".download", ".loan", ".accountant", ".stream",
    ".science", ".party", ".review", ".country", ".kim",
]

BULLETPROOF_KEYWORDS = [
    "vdsina", "selectel", "combahton", "frantech",
    "serverius", "quasi", "inferno", "hostkey",
    "colocrossing", "choopa",
]

HIGH_RISK_COUNTRIES = ["RU", "UA", "CN", "KP", "IR", "RO", "NG"]

PHISHING_STRIP_WORDS = [
    "secure", "update", "login", "verify", "bank", "account", "pay",
    "payment", "signin", "auth", "support", "service", "online",
    "portal", "official", "safe", "web", "app", "mobile", "net",
]

WELL_KNOWN_LEGIT = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "twitter.com",
    "linkedin.com", "instagram.com", "youtube.com", "github.com",
]


# ─── Helper: format domain age ──────────────────────────────────────────────

def format_age(days: int) -> str:
    """Human-readable domain age string."""
    if days <= 0:
        return "Unknown"
    if days < 7:
        return f"{days} day{'s' if days > 1 else ''}"
    if days < 30:
        w = days // 7
        return f"{w} week{'s' if w > 1 else ''}"
    if days < 365:
        m = days // 30
        return f"{m} month{'s' if m > 1 else ''}"
    years = days // 365
    months = (days % 365) // 30
    if months > 0:
        return f"{years}y {months}m"
    return f"{years} year{'s' if years > 1 else ''}"


# ─── Feature extractors ─────────────────────────────────────────────────────

async def _extract_whois(domain: str) -> dict:
    """WHOIS lookup: domain age, registrar, expiry."""
    try:
        loop = asyncio.get_event_loop()
        w = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain), timeout=8.0
        )
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
        else:
            age_days = 1

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        return {
            "domain_age_days": max(1, age_days),
            "registrar": w.registrar or "Unknown",
            "expiry_date": str(expiry) if expiry else "Unknown",
        }
    except Exception:
        return {"domain_age_days": 1, "registrar": "Unknown", "expiry_date": "Unknown"}


async def _extract_mx(domain: str) -> int:
    """Check for MX records."""
    try:
        loop = asyncio.get_event_loop()
        answers = await asyncio.wait_for(
            loop.run_in_executor(None, dns_resolver.resolve, domain, "MX"),
            timeout=5.0,
        )
        return 1 if len(answers) > 0 else 0
    except Exception:
        return 0


async def _extract_spf(domain: str) -> int:
    """Check for SPF TXT record."""
    try:
        loop = asyncio.get_event_loop()
        answers = await asyncio.wait_for(
            loop.run_in_executor(None, dns_resolver.resolve, domain, "TXT"),
            timeout=5.0,
        )
        for rdata in answers:
            txt = rdata.to_text().lower()
            if "v=spf1" in txt:
                return 1
        return 0
    except Exception:
        return 0


async def _extract_dmarc(domain: str) -> int:
    """Check for DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        loop = asyncio.get_event_loop()
        answers = await asyncio.wait_for(
            loop.run_in_executor(None, dns_resolver.resolve, dmarc_domain, "TXT"),
            timeout=5.0,
        )
        for rdata in answers:
            txt = rdata.to_text().lower()
            if "v=dmarc1" in txt:
                return 1
        return 0
    except Exception:
        return 0


async def _extract_tls(domain: str) -> dict:
    """Check TLS certificate validity and age."""
    tls_valid = 0
    tls_age_days = 0
    tls_issuer = "Unknown"

    # Try with full verification first
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _connect_ssl():
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=domain,
            ) as ssock:
                ssock.settimeout(6)
                ssock.connect((domain, 443))
                cert = ssock.getpeercert()
                return cert

        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _connect_ssl), timeout=6.0
        )
        tls_valid = 1
        # Parse cert dates
        not_before_str = cert.get("notBefore", "")
        if not_before_str:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            tls_age_days = (datetime.now() - not_before).days
        # Parse issuer
        issuer = cert.get("issuer", ())
        for field in issuer:
            for key, value in field:
                if key == "organizationName":
                    tls_issuer = value
                    break

    except ssl.SSLCertVerificationError:
        # Self-signed or invalid cert — try again without verification
        tls_valid = 0
        try:
            ctx_noverify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            loop = asyncio.get_event_loop()

            def _connect_noverify():
                with ctx_noverify.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=domain,
                ) as ssock:
                    ssock.settimeout(6)
                    ssock.connect((domain, 443))
                    cert_bin = ssock.getpeercert(binary_form=True)
                    return cert_bin

            cert_bin = await asyncio.wait_for(
                loop.run_in_executor(None, _connect_noverify), timeout=6.0
            )
            if cert_bin:
                try:
                    from OpenSSL import crypto
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    not_before = datetime.strptime(
                        x509.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ"
                    )
                    tls_age_days = (datetime.now() - not_before).days
                    tls_issuer = "Self-signed"
                    issuer_obj = x509.get_issuer()
                    if issuer_obj.O:
                        tls_issuer = issuer_obj.O
                except Exception:
                    tls_issuer = "Self-signed"
        except Exception:
            pass

    except Exception:
        pass

    return {
        "tls_valid": tls_valid,
        "tls_age_days": max(0, tls_age_days),
        "tls_issuer": tls_issuer,
    }


async def _extract_abuseipdb(ip: str) -> int:
    """Query AbuseIPDB for IP abuse confidence score."""
    if not ABUSEIPDB_API_KEY or "PASTE" in ABUSEIPDB_API_KEY or not ip:
        return 0
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=8.0, read=10.0)
        ) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
            if resp.status_code == 200:
                data = resp.json()
                return int(data.get("data", {}).get("abuseConfidenceScore", 0))
    except Exception:
        pass
    return 0


async def _extract_virustotal(domain: str) -> dict:
    """Query VirusTotal for domain reputation."""
    if not VIRUSTOTAL_API_KEY or "PASTE" in VIRUSTOTAL_API_KEY:
        return {"vt_malicious_count": 0, "vt_display": "API key not configured"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=8.0, read=15.0)
        ) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={
                    "x-apikey": VIRUSTOTAL_API_KEY,
                    "Accept": "application/json",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}
                )
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                return {
                    "vt_malicious_count": malicious,
                    "vt_display": f"{malicious} engines flagged as malicious",
                }
            elif resp.status_code in (404, 429):
                return {"vt_malicious_count": 0, "vt_display": "Not scanned"}
    except Exception:
        pass
    return {"vt_malicious_count": 0, "vt_display": "Error"}


async def _extract_asn(ip: str) -> dict:
    """IPWhois lookup: ASN info, bulletproof detection."""
    if not ip:
        return {
            "is_bulletproof_asn": 0,
            "ip_country": "Unknown",
            "asn_display": "Unknown",
        }
    try:
        from ipwhois import IPWhois

        loop = asyncio.get_event_loop()

        def _lookup():
            obj = IPWhois(ip)
            return obj.lookup_rdap(depth=1)

        result = await asyncio.wait_for(
            loop.run_in_executor(None, _lookup), timeout=5.0
        )
        asn_desc = (result.get("asn_description") or "").lower()
        country = result.get("asn_country_code") or "Unknown"
        is_bp = 0
        if any(kw in asn_desc for kw in BULLETPROOF_KEYWORDS):
            is_bp = 1
        if country in HIGH_RISK_COUNTRIES:
            is_bp = 1
        asn_display = f"{result.get('asn_description', 'Unknown')}, {country}"
        return {
            "is_bulletproof_asn": is_bp,
            "ip_country": country,
            "asn_display": asn_display,
        }
    except Exception:
        return {
            "is_bulletproof_asn": 0,
            "ip_country": "Unknown",
            "asn_display": "Unknown",
        }


async def _extract_redirects(domain: str) -> int:
    """Count HTTP redirects (max 10 hops)."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=8.0, verify=False
        ) as client:
            count = 0
            url = f"https://{domain}"
            for _ in range(10):
                resp = await client.get(url)
                if resp.status_code in (301, 302, 303, 307, 308):
                    url = resp.headers.get("location", "")
                    if not url:
                        break
                    # Handle relative redirects
                    if url.startswith("/"):
                        url = f"https://{domain}{url}"
                    count += 1
                else:
                    break
            return count
    except Exception:
        return 0


def _extract_url_length(original_url: str) -> int:
    """Length of the original URL string."""
    return len(original_url.strip())


def _extract_subdomain_depth(domain: str) -> int:
    """Number of subdomain levels (google.com=0, mail.google.com=1)."""
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def _extract_suspicious_keywords(domain: str) -> int:
    """Check for phishing keywords in the domain."""
    d = domain.lower()
    return 1 if any(kw in d for kw in SUSPICIOUS_KEYWORDS) else 0


def _extract_suspicious_tld(domain: str) -> int:
    """Check if the TLD is a known suspicious one."""
    tld = "." + domain.split(".")[-1].lower()
    return 1 if tld in SUSPICIOUS_TLDS else 0


# ─── Similar domains via URLScan.io ──────────────────────────────────────────

async def _find_similar_domains(domain: str) -> list[dict]:
    """Find similar suspicious domains via URLScan.io."""
    # Extract brand keyword
    parts = domain.split(".")
    # Remove TLD and last part
    name_parts = parts[:-1] if len(parts) > 1 else parts
    name_str = "-".join(name_parts).lower()

    # Split on hyphens and other separators
    import re
    words = re.split(r"[-_.]", name_str)
    # Remove common phishing words
    filtered = [w for w in words if w and w not in PHISHING_STRIP_WORDS and len(w) >= 3]

    if not filtered:
        return []

    # Use longest word as brand keyword
    brand = max(filtered, key=len)

    if len(brand) < 3:
        return []

    # Skip generic words
    generic = {"www", "com", "org", "the", "and", "for", "new", "get"}
    if brand in generic:
        return []

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=8.0, read=12.0)
        ) as client:
            resp = await client.get(
                "https://urlscan.io/api/v1/search/",
                headers={
                    "Accept": "application/json",
                    "User-Agent": get_random_ua(),
                },
                params={
                    "q": f"domain:{brand}*",
                    "size": 100,
                },
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            results = data.get("results", [])

            # Extract unique candidate domains
            seen = set()
            candidates = []
            for r in results:
                d = r.get("page", {}).get("domain", "")
                if d and d != domain and d not in seen and d not in WELL_KNOWN_LEGIT:
                    seen.add(d)
                    candidates.append(d)
                if len(candidates) >= 20:
                    break

            # DNS resolution check + similarity scoring
            from rapidfuzz import fuzz

            scored = []
            for cand in candidates:
                # Quick DNS check
                try:
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, cand),
                        timeout=2.0,
                    )
                except Exception:
                    continue  # Skip non-resolving domains

                match_pct = fuzz.token_set_ratio(domain, cand)

                # Quick risk label
                has_kw = any(kw in cand.lower() for kw in SUSPICIOUS_KEYWORDS)
                cand_tld = "." + cand.split(".")[-1].lower()
                has_sus_tld = cand_tld in SUSPICIOUS_TLDS

                if match_pct >= 70 or has_kw or has_sus_tld:
                    risk_label = "HIGH"
                elif match_pct >= 45:
                    risk_label = "MED"
                else:
                    risk_label = "LOW"

                scored.append({
                    "domain": cand,
                    "match_pct": match_pct,
                    "risk_label": risk_label,
                })

            # Sort by match % descending, take top 5
            scored.sort(key=lambda x: x["match_pct"], reverse=True)
            return scored[:5]

    except Exception:
        return []


# ─── Main endpoint ───────────────────────────────────────────────────────────

@router.post("/phishing-detect")
async def phishing_detect(target_url: str = Query(..., description="URL to analyse")):
    """
    Analyse a URL for phishing indicators using 10 OSINT signals,
    an XGBoost model with SHAP explanations, and similar domain discovery.
    """
    start_time = time.time()

    # STEP 1 — URL normalisation
    original_url = target_url.strip()
    domain = extract_domain(original_url)
    if not domain or len(domain) < 3:
        raise HTTPException(status_code=400, detail="Invalid domain or URL")

    # STEP 2 — Resolve IP
    ip = ""
    try:
        loop = asyncio.get_event_loop()
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, domain),
            timeout=5.0,
        )
    except Exception:
        ip = ""

    # STEP 3 — Feature extraction (all concurrently)
    (
        whois_data,
        has_mx,
        has_spf,
        has_dmarc,
        tls_data,
        abuseipdb_score,
        vt_data,
        asn_data,
        redirect_count,
    ) = await asyncio.gather(
        _extract_whois(domain),
        _extract_mx(domain),
        _extract_spf(domain),
        _extract_dmarc(domain),
        _extract_tls(domain),
        _extract_abuseipdb(ip),
        _extract_virustotal(domain),
        _extract_asn(ip),
        _extract_redirects(domain),
        return_exceptions=True,
    )

    # Handle any exceptions that were returned
    if isinstance(whois_data, Exception):
        whois_data = {"domain_age_days": 1, "registrar": "Unknown", "expiry_date": "Unknown"}
    if isinstance(has_mx, Exception):
        has_mx = 0
    if isinstance(has_spf, Exception):
        has_spf = 0
    if isinstance(has_dmarc, Exception):
        has_dmarc = 0
    if isinstance(tls_data, Exception):
        tls_data = {"tls_valid": 0, "tls_age_days": 0, "tls_issuer": "Unknown"}
    if isinstance(abuseipdb_score, Exception):
        abuseipdb_score = 0
    if isinstance(vt_data, Exception):
        vt_data = {"vt_malicious_count": 0, "vt_display": "Error"}
    if isinstance(asn_data, Exception):
        asn_data = {"is_bulletproof_asn": 0, "ip_country": "Unknown", "asn_display": "Unknown"}
    if isinstance(redirect_count, Exception):
        redirect_count = 0

    # Synchronous features
    domain_age_days = whois_data["domain_age_days"]
    tls_valid = tls_data["tls_valid"]
    tls_age_days = tls_data["tls_age_days"]
    tls_issuer = tls_data["tls_issuer"]
    vt_malicious_count = vt_data["vt_malicious_count"]
    is_bulletproof_asn = asn_data["is_bulletproof_asn"]
    ip_country = asn_data["ip_country"]
    asn_display = asn_data["asn_display"]
    url_length = _extract_url_length(original_url)
    subdomain_depth = _extract_subdomain_depth(domain)
    has_suspicious_keywords = _extract_suspicious_keywords(domain)
    is_suspicious_tld = _extract_suspicious_tld(domain)

    # STEP 4 — Build feature vector and run model
    feature_vector = {
        "domain_age_days": domain_age_days,
        "has_mx": has_mx,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "tls_valid": tls_valid,
        "tls_age_days": tls_age_days,
        "abuseipdb_score": abuseipdb_score,
        "vt_malicious_count": vt_malicious_count,
        "is_bulletproof_asn": is_bulletproof_asn,
        "url_length": url_length,
        "redirect_count": redirect_count,
        "subdomain_depth": subdomain_depth,
        "has_suspicious_keywords": has_suspicious_keywords,
        "is_suspicious_tld": is_suspicious_tld,
    }

    result = predict(feature_vector)

    # Raw data for OSINT display
    raw_data = {
        "domain_age": format_age(domain_age_days),
        "tls_issuer": tls_issuer,
        "asn_display": asn_display,
    }
    osint_display = build_osint_display(feature_vector, raw_data)

    # STEP 5 — Find similar suspicious domains
    similar_domains = await _find_similar_domains(domain)

    scan_duration = round(time.time() - start_time, 1)

    # STEP 7 — Build and return response
    return JSONResponse(content={
        "success": True,
        "message": f"Phishing analysis completed for {domain} in {scan_duration}s",
        "data": {
            "target_url": original_url,
            "target_domain": domain,
            "scan_duration": scan_duration,
            "risk_score": result["risk_score"],
            "verdict": result["verdict"],
            "risk_badge": result["badge"],
            "color_key": result["color_key"],
            "domain_age": format_age(domain_age_days),
            "domain_age_days": domain_age_days,
            "ip_address": ip,
            "ip_country": ip_country,
            "ip_abuse_score": abuseipdb_score,
            "vt_malicious_count": vt_malicious_count,
            "asn_display": asn_display,
            "tls_issuer": tls_issuer,
            "osint_features": osint_display,
            "shap_features": result["shap_features"],
            "conclusion_text": result["conclusion_text"],
            "similar_domains": similar_domains,
            "feature_vector": feature_vector,
        },
    })
