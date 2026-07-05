"""
routers/contact_scraper.py

Tool 2 — Contact & Email Scraper
Crawls a website's key pages (home, contact, about, team, footer)
and extracts:
  • Email addresses (with source page + smart classification)
  • Phone numbers  (validated via Google's libphonenumber)
  • Social media links (LinkedIn, Twitter/X, Facebook, Instagram, GitHub, YouTube)
  • Addresses & location info from schema.org / meta tags
  • Security notes about risky email patterns

Email classification tiers:
  1. generic    — role-based prefixes (info@, admin@, etc.)
  2. personal   — domain matches target exactly or is a subdomain
  3. affiliated — domain shares the same SLD family (e.g. szabist-isb.edu.pk ↔ szabist.edu.pk)
  4. external   — none of the above
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse
from typing import Optional

import httpx
import phonenumbers
from phonenumbers import geocoder as ph_geocoder
from bs4 import BeautifulSoup
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse

from utils.helpers import extract_domain, get_base_url, get_random_ua, COMMON_HEADERS

router = APIRouter()

# ─── Regex patterns ───────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}\b"
)

_SOCIAL_PATTERNS: dict[str, re.Pattern] = {
    "LinkedIn":  re.compile(r"linkedin\.com/(?:company|in|school|pub)/[a-zA-Z0-9_\-%.]+", re.I),
    "Twitter/X": re.compile(r"(?:twitter|x)\.com/[a-zA-Z0-9_]{1,50}", re.I),
    "Facebook":  re.compile(r"facebook\.com/(?:pages/)?[a-zA-Z0-9._%\-]+", re.I),
    "Instagram": re.compile(r"instagram\.com/[a-zA-Z0-9_.]{1,30}", re.I),
    "GitHub":    re.compile(r"github\.com/[a-zA-Z0-9_\-]{1,39}", re.I),
    "YouTube":   re.compile(r"youtube\.com/(?:channel|user|c|@)[/a-zA-Z0-9_\-]+", re.I),
    "TikTok":    re.compile(r"tiktok\.com/@[a-zA-Z0-9_.]{1,24}", re.I),
}

# Generic / role-based email prefixes that indicate security risk
_GENERIC_PREFIXES = {
    "info", "contact", "admin", "webmaster", "support",
    "hello", "noreply", "no-reply", "mail", "office",
    "team", "hr", "sales", "marketing", "careers",
    "feedback", "help", "service", "enquiry", "enquiries",
}

# Pages to crawl on target domain
_TARGET_PATHS = [
    "/",
    "/contact",
    "/contact-us",
    "/contacts",
    "/contactus",
    "/reach-us",
    "/get-in-touch",
    "/connect",
    "/about",
    "/about-us",
    "/aboutus",
    "/team",
    "/our-team",
    "/staff",
    "/faculty",           # universities
    "/people",
    "/directory",
]


# ─── Smart email classification ───────────────────────────────────────────────

def _extract_sld(domain: str) -> str:
    """
    Extract the meaningful Second-Level Domain part.
    'szabist.edu.pk'     → 'szabist'
    'szabist-isb.edu.pk' → 'szabist-isb'
    'zabsolutions.com'   → 'zabsolutions'
    Handles country-code TLDs with 2-part suffixes (.edu.pk, .ac.ae, .co.uk)
    """
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 3:
        # Could be a ccTLD like .edu.pk — SLD is parts[-3]
        return parts[-3] if len(parts[-2]) <= 3 else parts[-2]
    elif len(parts) == 2:
        return parts[0]
    return domain


def _classify_email(email: str, base_domain: str) -> str:
    """
    Classify email as: 'generic', 'personal', 'affiliated', or 'external'

    Classification rules (domain takes priority over prefix):
    1. If domain is completely unrelated → 'external'
    2. If domain is a related/sibling domain → 'affiliated'
    3. If domain matches exactly (or is subdomain) AND has a role-based
       prefix (info@, admin@, etc.) → 'generic'
    4. If domain matches exactly (or is subdomain) AND has a non-role
       prefix → 'personal'

    This ensures that info@other-company.com is correctly classified as
    'external' rather than 'generic'.
    """
    prefix = email.split('@')[0].lower()
    email_domain = email.split('@')[1].lower()

    # Check 1: exact domain match (personal or generic)
    if email_domain == base_domain or email_domain.endswith(f'.{base_domain}'):
        # Same domain — now check if prefix is role-based
        if prefix.strip('+. ') in _GENERIC_PREFIXES:
            return 'generic'
        return 'personal'

    # Check 2: affiliated — extract SLD from base domain and check overlap
    base_sld = _extract_sld(base_domain)
    email_sld = _extract_sld(email_domain)

    if base_sld and (
        base_sld == email_sld or
        base_sld in email_sld or          # 'szabist' in 'szabist-isb'
        email_sld in base_sld
    ):
        return 'affiliated'

    # Check 3: external — none of the above
    return 'external'


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_emails(text: str, html: str, source_page: str, base_domain: str) -> list[dict]:
    """Find all email addresses in text + raw HTML with smart classification."""
    combined = f"{text} {html}"
    found: dict[str, dict] = {}
    for match in _EMAIL_RE.finditer(combined):
        addr = match.group(0).lower().strip(".")
        # Filter out obvious false positives (image files, etc.)
        if addr.split(".")[-1] in ("png", "jpg", "gif", "svg", "css", "js", "ico"):
            continue
        if addr not in found:
            found[addr] = {
                "email":       addr,
                "source_page": source_page,
                "type":        _classify_email(addr, base_domain),
            }
    return list(found.values())


def _extract_phones(text: str, source_page: str) -> list[dict]:
    """Extract and validate phone numbers using Google's libphonenumber."""
    results: list[dict] = []
    seen: set[str] = set()
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, None):
            num = match.number
            intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            if intl in seen:
                continue
            seen.add(intl)
            results.append({
                "number":      intl,
                "national":    phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
                "country":     ph_geocoder.description_for_number(num, "en"),
                "source_page": source_page,
            })
    except Exception:
        pass
    return results


def _is_valid_social_url(href: str) -> bool:
    """
    Quality-check a candidate social media URL.
    Rejects anchor-only / fragment-only links (e.g. twitter.com/shayari/#),
    bare domains without a real profile path, and javascript: hrefs.
    """
    clean = href.split("#")[0].rstrip("/")
    if not clean or clean in ("#", "javascript:void(0)"):
        return False
    parsed = urlparse(clean if clean.startswith("http") else f"https://{clean}")
    path = parsed.path.strip("/")
    if not path:
        return False
    if path.startswith(("share", "intent", "sharer", "dialog")):
        return False
    return True


def _normalise_social_url(href: str) -> str:
    """Normalise a social URL: ensure https, lowercase domain."""
    if not href.startswith("http"):
        href = f"https://{href.lstrip('/')}"
    # Strip fragment
    href = href.split("#")[0].rstrip("/")
    parsed = urlparse(href)
    return f"https://{parsed.netloc.lower()}{parsed.path}"


def _extract_socials(soup: BeautifulSoup) -> list[dict]:
    """Find social media links from anchor tags on the page."""
    results: list[dict] = []
    seen_urls: set[str] = set()

    for a in soup.find_all("a", href=True):
        href: str = a["href"].strip()
        for platform, pattern in _SOCIAL_PATTERNS.items():
            if pattern.search(href) and _is_valid_social_url(href):
                canonical = _normalise_social_url(href)
                if canonical not in seen_urls:
                    seen_urls.add(canonical)
                    results.append({"platform": platform, "url": canonical})
                break

    return results


_ADDRESS_RE = re.compile(
    r'(?:'
    r'\d{1,5}\s+[A-Z][a-zA-Z\s,.\-]{5,80}'
    r'(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|'
    r'Way|Block|Plot|Sector|Phase|Highway|Hwy|Square|Plaza)'
    r'[a-zA-Z0-9\s,.#\-]{0,120}'
    r')',
    re.IGNORECASE,
)


def _extract_address(soup: BeautifulSoup, page_text: str = "") -> Optional[str]:
    """
    Try to find a physical address via:
      1. schema.org PostalAddress (itemprop)
      2. <address> HTML element
      3. Plain-text regex fallback on page body
    """
    # 1. schema.org PostalAddress
    for tag in soup.find_all(attrs={"itemprop": "streetAddress"}):
        text = tag.get_text(strip=True)
        if text:
            return text

    # Also check for full schema.org address block
    for tag in soup.find_all(attrs={"itemprop": "address"}):
        text = tag.get_text(separator=", ", strip=True)
        if len(text) > 10:
            return text

    # 2. <address> HTML element
    for tag in soup.find_all("address"):
        text = tag.get_text(separator=", ", strip=True)
        if len(text) > 10:
            return text

    # 3. Plain-text regex fallback
    if page_text:
        match = _ADDRESS_RE.search(page_text)
        if match:
            addr = match.group(0).strip().rstrip(",. ")
            if len(addr) > 15:
                return addr

    return None


# ─── Async page fetcher ────────────────────────────────────────────────────────

async def _fetch_page(client: httpx.AsyncClient, url: str) -> Optional[tuple[str, str]]:
    """
    Fetch one page.  Returns (text_content, raw_html) or None on failure.
    Tries the supplied URL first; silently fails on 4xx / 5xx.
    """
    headers = {"User-Agent": get_random_ua(), **COMMON_HEADERS}
    try:
        resp = await client.get(url, headers=headers, follow_redirects=True)
        if resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
            soup = BeautifulSoup(resp.text, "lxml")
            # Strip scripts/styles before extracting text
            for tag in soup(["script", "style", "noscript", "head"]):
                tag.decompose()
            return soup.get_text(separator=" "), str(soup)
    except Exception:
        pass
    return None


# ─── Main route ───────────────────────────────────────────────────────────────

@router.post("/contact-scrape")
async def contact_scrape(
    target_url: str = Query(..., description="Target website URL (e.g. https://example.com)"),
):
    """
    **Contact & Email Scraper**

    Crawls the home page, contact, about, team, and directory pages.
    Extracts email addresses (with source attribution), phone numbers,
    social media links, physical address, and highlights security risks.

    Email classification:
      generic    — role-based (info@, admin@)
      personal   — matches target domain exactly
      affiliated — related domain family (e.g. szabist-isb.edu.pk for szabist.edu.pk)
      external   — unrelated domain
    """
    start_time = time.time()

    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    base_url = get_base_url(target_url)
    domain   = extract_domain(target_url)

    # Aggregation containers
    all_emails: dict[str, dict]  = {}
    all_phones: dict[str, dict]  = {}
    all_socials: list[dict]       = []
    seen_social_urls: set[str]    = set()
    pages_scanned:  list[str]     = []
    found_address:  Optional[str] = None

    try:
        async with httpx.AsyncClient(timeout=12.0, verify=False) as client:

            # Build URL list — always include the base, then try common paths
            urls_to_scan = [urljoin(base_url, path) for path in _TARGET_PATHS]

            # Fetch all pages concurrently
            tasks   = [_fetch_page(client, url) for url in urls_to_scan]
            results = await asyncio.gather(*tasks)

            for page_url, result in zip(urls_to_scan, results):
                if result is None:
                    continue

                text, raw_html = result
                soup = BeautifulSoup(raw_html, "lxml")
                path = "/" + page_url.replace(base_url, "").lstrip("/")
                pages_scanned.append(path if path != "//" else "/")

                # ── Emails ────────────────────────────────────────────────
                for entry in _extract_emails(text, raw_html, path, domain):
                    addr = entry["email"]
                    if addr not in all_emails:
                        all_emails[addr] = entry

                # ── Phone numbers ─────────────────────────────────────────
                for phone in _extract_phones(text, path):
                    num = phone["number"]
                    if num not in all_phones:
                        all_phones[num] = phone

                # ── Social links ──────────────────────────────────────────
                for social in _extract_socials(soup):
                    if social["url"] not in seen_social_urls:
                        seen_social_urls.add(social["url"])
                        all_socials.append(social)

                # ── Physical address (first match wins) ───────────────────
                if found_address is None:
                    found_address = _extract_address(soup, text)

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scraping failed: {str(exc)}")

    # ── Build ordered email list ──────────────────────────────────────────────
    emails_detailed = list(all_emails.values())
    # Sort order: generic → personal → affiliated → external
    _type_order = {"generic": 0, "personal": 1, "affiliated": 2, "external": 3}
    emails_detailed.sort(key=lambda e: (_type_order.get(e.get("type", "external"), 3), e["email"]))

    # ── Security analysis ─────────────────────────────────────────────────────
    generic_count    = sum(1 for e in emails_detailed if e.get("type") == "generic")
    external_count   = sum(1 for e in emails_detailed if e.get("type") == "external")
    affiliated_count = sum(1 for e in emails_detailed if e.get("type") == "affiliated")

    security_notes: list[str] = []
    if generic_count:
        security_notes.append(
            f"{generic_count} generic role-based email(s) found (e.g. info@, admin@) "
            f"— easy phishing targets; consider restricting visibility."
        )
    if external_count > 0:
        security_notes.append(
            f"{external_count} external-domain email(s) found — "
            f"verify they are intentional."
        )
    if affiliated_count > 0:
        security_notes.append(
            f"{affiliated_count} affiliated organization email(s) found "
            f"(related domains detected — likely intentional)."
        )
    if not all_phones:
        security_notes.append(
            "No phone numbers detected — contact information may be incomplete."
        )

    scan_duration = round(time.time() - start_time, 2)

    return JSONResponse(content={
        "success": True,
        "message": f"Contact scrape completed for {domain} — "
                   f"{len(emails_detailed)} email(s), {len(all_phones)} phone(s), "
                   f"{len(all_socials)} social link(s) found in {scan_duration}s",
        "data": {
            "target_url":      target_url,
            "target_domain":   domain,
            # Simple list (what Flutter scan_screen currently reads)
            "emails":          [e["email"] for e in emails_detailed],
            # Rich list with source + type (used by export & future rich UI)
            "emails_detailed": emails_detailed,
            "email_count":     len(emails_detailed),
            "phone_numbers":   list(all_phones.values()),
            "phone_count":     len(all_phones),
            "social_links":    all_socials,
            "social_count":    len(all_socials),
            "address":         found_address,
            "pages_scanned":   pages_scanned,
            "scan_duration":   scan_duration,
            "security_notes":  security_notes,
        },
    })
