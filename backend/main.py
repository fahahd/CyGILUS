"""
CyGILUS Backend API
FastAPI-powered OSINT security tool backend
Supports: Windows, macOS, Linux
"""

import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from routers import dns_scanner, contact_scraper, export, phishing_detector


# ─── Lifespan ─────────────────────────────────────────────────────────────────

def _mask_key(key: str) -> str:
    """Helper to mask API keys for logging."""
    if not key or "PASTE" in key:
        return "Not configured"
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown logic."""
    # Ensure the temp export directory exists on startup
    export_dir = os.path.join(os.path.dirname(__file__), "exports")
    os.makedirs(export_dir, exist_ok=True)
    
    abuseip_masked = _mask_key(phishing_detector.ABUSEIPDB_API_KEY)
    vt_masked = _mask_key(phishing_detector.VIRUSTOTAL_API_KEY)
    
    print(f"\n[OK]  CyGILUS Backend running  ->  http://localhost:8000")
    print(f"[KEY] AbuseIPDB API Key        ->  {abuseip_masked}")
    print(f"[KEY] VirusTotal API Key       ->  {vt_masked}")
    print(f"[DIR] Export directory         ->  {export_dir}")
    print(f"[API] API Docs                 ->  http://localhost:8000/docs\n")
    yield
    # Cleanup on shutdown (optional: remove old export files)
    print("\n[STOP] CyGILUS Backend shutting down...")


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyGILUS API",
    description="Cross-platform OSINT cybersecurity scanner backend",
    version="1.0.0",
    lifespan=lifespan,
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
# Allow Flutter web (localhost:3000), desktop, and any LAN IP during dev

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "*",          # wide-open during development; restrict in production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],  # needed for file downloads
)


# ─── Global exception handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": f"Internal server error: {str(exc)}",
        },
    )


# ─── Routers ──────────────────────────────────────────────────────────────────

app.include_router(dns_scanner.router,        prefix="/api/tools",  tags=["DNS Scanner"])
app.include_router(contact_scraper.router,    prefix="/api/tools",  tags=["Contact Scraper"])
app.include_router(phishing_detector.router,  prefix="/api/tools",  tags=["Phishing Detector"])
app.include_router(export.router,             prefix="/api/export",  tags=["Export"])


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def root():
    return {
        "success": True,
        "message": "CyGILUS Backend API is running",
        "version": "1.0.0",
        "endpoints": {
            "dns_scan":        "POST /api/tools/dns-scan?target_url=<domain>",
            "contact_scrape":  "POST /api/tools/contact-scrape?target_url=<url>",
            "phishing_detect": "POST /api/tools/phishing-detect?target_url=<url>",
            "export_generate": "POST /api/export/generate",
            "export_download": "GET  /api/export/download/<filename>",
            "docs":            "GET  /docs",
        },
    }

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
