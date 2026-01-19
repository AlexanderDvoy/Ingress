from __future__ import annotations
from typing import Any, Dict, List, Optional
import re

"""
Best-effort organization attribution (observed/inferred), based on public indicators.
This is NOT ownership proof. Always treat as a hint with confidence level.
"""

COMPANY_STOPWORDS = {
    "www", "mail", "smtp", "imap", "pop", "vpn", "rdp", "ssh", "admin", "portal",
    "cpanel", "panel", "web", "api", "app", "apps", "auth", "login", "gateway",
}

def _normalize_token(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9\-]", "", s)
    return s

def _extract_brand_from_hostname(hostname: str) -> Optional[str]:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) < 2:
        return None
    candidate = _normalize_token(parts[-2])
    if not candidate or candidate in COMPANY_STOPWORDS:
        return None
    return candidate

def infer_organization(asset: Dict[str, Any]) -> Dict[str, Any]:
    sources: List[str] = []
    confidence = "Low"
    observed_org: Optional[str] = None

    # 1) TLS certificate CN / SAN (often strongest)
    ssl = asset.get("ssl") or {}
    cert = (ssl.get("cert") or {}) if isinstance(ssl, dict) else {}
    subject = cert.get("subject") or {}
    cn = subject.get("CN") if isinstance(subject, dict) else None

    san = None
    ext = cert.get("extensions") or {}
    if isinstance(ext, dict):
        san = ext.get("subjectAltName")

    def _pick_from_san(value: str) -> Optional[str]:
        dnsnames = re.findall(r"DNS:([A-Za-z0-9\-\._]+)", value)
        for dn in dnsnames:
            brand = _extract_brand_from_hostname(dn.replace("*.", ""))
            if brand:
                return brand
        return None

    if isinstance(cn, str) and cn.strip():
        brand = _extract_brand_from_hostname(cn) if "." in cn else _normalize_token(cn)
        if brand:
            observed_org = brand
            sources.append("ssl_cn")
            confidence = "High"

    if observed_org is None and isinstance(san, str) and san.strip():
        brand = _pick_from_san(san)
        if brand:
            observed_org = brand
            sources.append("ssl_san")
            confidence = "High"

    # 2) Hostnames/domains
    if observed_org is None:
        for h in asset.get("hostnames", []) or []:
            if isinstance(h, str) and "." in h:
                brand = _extract_brand_from_hostname(h)
                if brand:
                    observed_org = brand
                    sources.append("hostname")
                    confidence = "Medium"
                    break

    if observed_org is None:
        for d in asset.get("domains", []) or []:
            if isinstance(d, str) and "." in d:
                brand = _extract_brand_from_hostname(d)
                if brand:
                    observed_org = brand
                    sources.append("domain")
                    confidence = "Medium"
                    break

    # 3) HTTP title (weak hint)
    http = asset.get("http") or {}
    title = http.get("title") if isinstance(http, dict) else None
    if observed_org is None and isinstance(title, str) and title.strip():
        tok = _normalize_token(title.split()[0])
        if tok and tok not in COMPANY_STOPWORDS and len(tok) >= 3:
            observed_org = tok
            sources.append("http_title")
            confidence = "Low"

    return {
        "observed_org": observed_org,
        "attribution_confidence": confidence,
        "attribution_sources": sources,
    }
