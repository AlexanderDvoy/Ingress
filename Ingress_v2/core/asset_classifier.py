from __future__ import annotations
from typing import Any, Dict, List

SERVICE_PROFILES = [
    {"name": "RDP", "ports": {3389}, "mitre": ["T1133"], "desc": "Remote Desktop exposed"},
    {"name": "SSH", "ports": {22}, "mitre": ["T1133"], "desc": "SSH exposed"},
    {"name": "VPN", "ports": {443, 8443, 500, 4500}, "mitre": ["T1133"], "desc": "Remote access/VPN portal likely"},
    {"name": "WEB_ADMIN", "ports": {80, 443, 8080, 8443}, "mitre": ["T1190"], "desc": "Potential public-facing admin/app"},
    {"name": "DB", "ports": {1433, 1521, 27017, 3306, 5432, 6379, 9200}, "mitre": ["T1133"], "desc": "Database/service exposed"},
]

KEYWORDS_ADMIN = ("admin", "dashboard", "control panel", "login", "signin", "manage")

def _guess_profile(asset: Dict[str, Any]) -> Dict[str, Any]:
    port = int(asset.get("port") or 0)
    product = (asset.get("product") or "").lower()
    banner = (asset.get("banner") or "").lower()

    for p in SERVICE_PROFILES:
        if port in p["ports"]:
            if p["name"] == "WEB_ADMIN":
                if any(k in banner for k in KEYWORDS_ADMIN) or any(k in product for k in KEYWORDS_ADMIN):
                    return p
                return {"name": "WEB", "ports": p["ports"], "mitre": ["T1190"], "desc": "Public web service"}
            return p

    if any(k in banner for k in KEYWORDS_ADMIN):
        return {"name": "WEB_ADMIN", "ports": set(), "mitre": ["T1190"], "desc": "Admin interface keywords present"}

    return {"name": "UNKNOWN", "ports": set(), "mitre": [], "desc": "Unclassified exposure"}

def classify_assets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for a in assets:
        profile = _guess_profile(a)
        a["category"] = profile["name"]
        a["category_desc"] = profile["desc"]
        a["mitre_techniques"] = profile.get("mitre", [])
    return assets
