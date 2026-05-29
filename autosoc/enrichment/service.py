#!/usr/bin/env python3
"""
Step 5a: Enrichment Service
Queries three free threat-intel APIs for IPs, domains, and URLs.

  enrich_ip(ip)         → AbuseIPDB
  enrich_domain(domain) → VirusTotal
  enrich_url(url)       → URLhaus

All functions are LRU-cached so each unique IOC is queried at most once per
run.  When API keys are absent (or a request fails) they return clearly-labelled
mock data so the rest of the pipeline keeps working.
"""

import sys
import json
import urllib.request
import urllib.parse
import urllib.error
from functools import lru_cache

# ── Config ────────────────────────────────────────────────────────────────────

try:
    sys.path.insert(0, ".")
    from config import ABUSEIPDB_API_KEY, VT_API_KEY
except ImportError:
    ABUSEIPDB_API_KEY = ""
    VT_API_KEY        = ""

REQUEST_TIMEOUT = 8   # seconds — generous but won't hang the CLI


# ── Shared HTTP helper ────────────────────────────────────────────────────────

def _get(url: str, headers: dict | None = None) -> dict | None:
    """
    Perform a GET request and return parsed JSON, or None on any error.
    Uses stdlib only — no requests dependency required.
    """
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _post_json(url: str, payload: dict, headers: dict | None = None) -> dict | None:
    """POST application/json and return parsed JSON, or None on error."""
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=data,
        headers={**(headers or {}), "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _post_form(url: str, fields: dict) -> dict | None:
    """POST application/x-www-form-urlencoded and return parsed JSON, or None."""
    data = urllib.parse.urlencode(fields).encode()
    req  = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


# ── Mock data helpers ─────────────────────────────────────────────────────────

def _mock_ip(ip: str) -> dict:
    return {
        "country":       "MOCK",
        "abuse_score":   0,
        "total_reports": 0,
        "is_malicious":  False,
        "_source":       "mock — add ABUSEIPDB_API_KEY to config.py",
    }


def _mock_domain(domain: str) -> dict:
    return {
        "malicious_votes": 0,
        "total_votes":     0,
        "reputation":      0,
        "is_malicious":    False,
        "_source":         "mock — add VT_API_KEY to config.py",
    }


def _mock_url(url: str) -> dict:
    return {
        "url_status":  "unknown",
        "threat_type": "none",
        "is_malicious": False,
        "_source":      "mock — URLhaus query failed",
    }


# ── IP enrichment (AbuseIPDB) ─────────────────────────────────────────────────

@lru_cache(maxsize=512)
def enrich_ip(ip: str) -> dict:
    from config import MOCK_MODE
    if MOCK_MODE:
        return {"country": "RU", "abuse_score": 85, "is_malicious": True}

    if not ABUSEIPDB_API_KEY:
        return _mock_ip(ip)

    params = urllib.parse.urlencode({
        "ipAddress":    ip,
        "maxAgeInDays": 90,
    })
    url  = f"https://api.abuseipdb.com/api/v2/check?{params}"
    data = _get(url, headers={
        "Key":    ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    })

    if data is None or "data" not in data:
        return _mock_ip(ip)

    d = data["data"]
    score = int(d.get("abuseConfidenceScore", 0))
    return {
        "country":       d.get("countryCode", "XX"),
        "abuse_score":   score,
        "total_reports": int(d.get("totalReports", 0)),
        "is_malicious":  score >= 50,
        "_source":       "abuseipdb",
    }


# ── Domain enrichment (VirusTotal) ────────────────────────────────────────────

@lru_cache(maxsize=512)
def enrich_domain(domain: str) -> dict:
    """
    Query VirusTotal v3 for domain reputation.

    Free-tier endpoint: GET /api/v3/domains/{domain}
    Required header:    x-apikey: <api_key>
    """
    from config import MOCK_MODE
    if MOCK_MODE:
        return {"malicious_votes": 10, "total_votes": 50, "is_malicious": True}

    if not VT_API_KEY:
        return _mock_domain(domain)

    url  = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
    data = _get(url, headers={"x-apikey": VT_API_KEY})

    if data is None or "data" not in data:
        return _mock_domain(domain)

    attrs  = data["data"].get("attributes", {})
    votes  = attrs.get("last_analysis_stats", {})
    mal    = int(votes.get("malicious",  0))
    susp   = int(votes.get("suspicious", 0))
    total  = sum(votes.values()) or 1        # avoid div-by-zero
    rep    = int(attrs.get("reputation", 0))

    return {
        "malicious_votes": mal + susp,
        "total_votes":     total,
        "reputation":      rep,
        "is_malicious":    (mal + susp) > 0 or rep < -10,
        "_source":         "virustotal",
    }


# ── URL enrichment (URLhaus) ──────────────────────────────────────────────────

@lru_cache(maxsize=512)
def enrich_url(url: str) -> dict:
    """
    Query URLhaus for URL status.

    No API key required.
    Endpoint: POST https://urlhaus-api.abuse.ch/v1/url/
    """
    from config import MOCK_MODE
    if MOCK_MODE:
        return {"url_status": "online", "threat_type": "phishing", "is_malicious": True}

    data = _post_form(
        "https://urlhaus-api.abuse.ch/v1/url/",
        {"url": url},
    )

    if data is None or data.get("query_status") == "no_results":
        return _mock_url(url)

    status  = data.get("url_status", "unknown")
    threats = data.get("tags") or []
    threat  = threats[0] if threats else (
        "malware" if status == "online" else "phishing"
    )

    return {
        "url_status":   status,
        "threat_type":  threat,
        "is_malicious": status in ("online", "malicious"),
        "_source":      "urlhaus",
    }


# ── Bulk enrichment convenience function ─────────────────────────────────────

def enrich_iocs(iocs: dict) -> dict:
    """
    Enrich all IOCs in the iocs dict and return a nested lookup dict:

    {
        "ips":     { "1.2.3.4":    <enrich_ip result>,    … },
        "domains": { "evil.cyou":  <enrich_domain result>, … },
        "urls":    { "/drop.exe":  <enrich_url result>,    … },
    }

    Each sub-dict key is the raw IOC string.
    LRU caching on the individual functions means no duplicate API calls.
    """
    results: dict = {"ips": {}, "domains": {}, "urls": {}}

    for ip in iocs.get("ips", []):
        results["ips"][ip] = enrich_ip(ip)

    for domain in iocs.get("domains", []):
        results["domains"][domain] = enrich_domain(domain)

    for url in iocs.get("urls", []):
        results["urls"][url] = enrich_url(url)

    return results
