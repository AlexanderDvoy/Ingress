from __future__ import annotations
from typing import Any, Dict, List
from pathlib import Path

def _risk_color(level: str) -> str:
    if level == "HIGH":
        return "red"
    if level == "MEDIUM":
        return "orange"
    return "green"

def build_attack_map(out_html: Path, assets: List[Dict[str, Any]], title: str = "Ingress Map") -> None:
    try:
        import folium  # type: ignore
        from folium.plugins import MarkerCluster  # type: ignore
    except Exception as e:
        raise RuntimeError("Missing dependency 'folium'. Did you run: pip install -r requirements.txt ?") from e

    m = folium.Map(location=[20, 0], zoom_start=2, tiles="OpenStreetMap", control_scale=True)
    cluster = MarkerCluster(name="Assets").add_to(m)

    plotted = 0
    for a in assets:
        geo = a.get("geo") or {}
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if lat is None or lon is None:
            continue

        ip = a.get("ip")
        port = a.get("port")
        cat = a.get("category")
        org = a.get("org") or "N/A"
        country = geo.get("country") or ""
        city = geo.get("city") or ""
        risk = a.get("risk_score")
        level = a.get("risk_level") or "LOW"
        mitre = ", ".join(a.get("mitre_techniques") or [])

        observed_org = a.get("observed_org") or "N/A"
        confidence = a.get("attribution_confidence") or "N/A"
        sources = ", ".join(a.get("attribution_sources") or []) or "N/A"
        note = a.get("attribution_note")
        note_html = f"<div style='font-size:11px;color:#666;margin-top:6px;'><i>{note}</i></div>" if note else ""

        popup_html = f"""
        <div style="font-family: Arial; width: 340px;">
          <h4 style="margin: 0 0 6px 0;">{ip}:{port}</h4>
          <div><b>Category:</b> {cat}</div>
          <div><b>Risk:</b> {risk} ({level})</div>
          <div><b>MITRE:</b> {mitre or '-'}</div>
          <div><b>Network Owner:</b> {org}</div>
          <div><b>Observed Org:</b> {observed_org}</div>
          <div><b>Attribution Confidence:</b> {confidence}</div>
          <div><b>Sources:</b> {sources}</div>
          {note_html}
          <div><b>Location:</b> {city} {country}</div>
        </div>
        """

        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=450),
            tooltip=f"{ip}:{port} • {cat} • {level}",
            icon=folium.Icon(color=_risk_color(level), icon="info-sign"),
        ).add_to(cluster)
        plotted += 1

    folium.LayerControl().add_to(m)

    title_html = f"""
         <div style="position: fixed; 
                     top: 10px; left: 50px; width: 440px; height: 58px; 
                     background-color: rgba(255, 255, 255, 0.85);
                     z-index:9999; font-size:16px; padding: 10px; border-radius: 10px;
                     box-shadow: 0 2px 8px rgba(0,0,0,0.15);">
             <b>{title}</b><br/>
             Plotted assets: {plotted}
         </div>
         """
    m.get_root().html.add_child(folium.Element(title_html))

    out_html.write_text(m.get_root().render(), encoding="utf-8")
