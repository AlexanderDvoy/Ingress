from __future__ import annotations
import os
from typing import Any, Dict, List

from dotenv import load_dotenv

def _require_env(key: str) -> str:
    val = os.getenv(key, "").strip()
    if not val:
        raise RuntimeError(
            f"Missing {key}. Create a .env file (copy from .env.example) and set {key}=..."
        )
    return val

def collect_shodan_assets(query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Collect results from Shodan for a given query.

    Returns a list of normalized asset dicts.
    """
    load_dotenv()
    api_key = _require_env("SHODAN_API_KEY")

    try:
        import shodan  # type: ignore
    except Exception as e:
        raise RuntimeError("Missing dependency 'shodan'. Did you run: pip install -r requirements.txt ?") from e

    api = shodan.Shodan(api_key)
    res = api.search(query)
    matches = (res.get("matches", []) or [])[: max(0, int(limit))]

    assets = []
    for m in matches:
        loc = m.get("location") or {}
        asset = {
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "transport": m.get("transport"),
            "org": m.get("org"),
            "isp": m.get("isp"),
            "asn": m.get("asn"),
            "hostnames": m.get("hostnames") or [],
            "domains": m.get("domains") or [],
            "product": m.get("product"),
            "version": m.get("version"),
            "tags": m.get("tags") or [],
            "timestamp": m.get("timestamp"),
            "banner": (m.get("data") or "")[:500],  # avoid dumping huge banners
            # Keep these for best-effort attribution
            "ssl": m.get("ssl"),
            "http": m.get("http"),
            "geo": {
                "country": loc.get("country_name"),
                "country_code": loc.get("country_code"),
                "city": loc.get("city"),
                "region_code": loc.get("region_code"),
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
            },
            "raw": {
                "shodan_id": m.get("_shodan", {}).get("id"),
                "opts": m.get("opts"),
            }
        }
        assets.append(asset)

    return assets
