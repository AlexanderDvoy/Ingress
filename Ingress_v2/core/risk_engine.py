from __future__ import annotations
from typing import Any, Dict, List

BASE_BY_CATEGORY = {
    "RDP": 85,
    "SSH": 65,
    "VPN": 75,
    "WEB_ADMIN": 80,
    "WEB": 55,
    "DB": 90,
    "UNKNOWN": 45,
}

BANNER_BONUSES = [
    ("default password", 15, "Banner suggests default credentials"),
    ("anonymous", 10, "Banner suggests anonymous access"),
    ("unauthorized", 10, "Banner suggests access control issues"),
    ("admin", 8, "Admin-related keywords"),
    ("login", 5, "Login/auth surface exposed"),
    ("test", 5, "Test environment markers"),
]

PRODUCT_PENALTIES = [
    ("nginx", -5, "Common web stack (lower confidence)"),
    ("apache", -5, "Common web stack (lower confidence)"),
]

def _clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, x))

def score_assets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for a in assets:
        cat = a.get("category") or "UNKNOWN"
        base = int(BASE_BY_CATEGORY.get(cat, 45))
        reasons = [f"Base score for category: {cat} = {base}"]

        banner = (a.get("banner") or "").lower()
        product = (a.get("product") or "").lower()

        score = base
        for kw, bonus, why in BANNER_BONUSES:
            if kw in banner:
                score += bonus
                reasons.append(f"+{bonus}: {why} ('{kw}')")

        for kw, penalty, why in PRODUCT_PENALTIES:
            if kw in product:
                score += penalty
                reasons.append(f"{penalty}: {why} ('{kw}')")

        geo = a.get("geo") or {}
        if geo.get("latitude") is None or geo.get("longitude") is None:
            score -= 5
            reasons.append("-5: Missing geo coordinates (lower confidence)")

        a["risk_score"] = _clamp(score)
        a["risk_reasons"] = reasons
        a["risk_level"] = ("HIGH" if a["risk_score"] >= 80 else "MEDIUM" if a["risk_score"] >= 60 else "LOW")
    return assets
