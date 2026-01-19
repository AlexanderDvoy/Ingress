# Ingress — Shodan-Driven Initial Access & Attack Surface Mapper

> **For authorized security assessments only.**  
Use this tool only on assets you own or have explicit written permission to test.

Ingress collects internet-exposed services from **Shodan**, classifies likely **Initial Access vectors**, scores exposure risk, generates **attack-path narratives** (descriptive, non-exploit), and renders an **interactive map (HTML)** of the results.

---

## What you get (Outputs)

After a run, Ingress generates 4 files inside `reports/`:

- `assets_<RUNID>.json` — normalized assets from Shodan (trimmed banners)
- `attack_paths_<RUNID>.json` — descriptive attack-path narratives (no exploitation)
- `report_<RUNID>.md` — Markdown report (GitHub-friendly)
- `ingress_map_<RUNID>.html` — **interactive real map** (Leaflet/Folium)

---

## Install

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## Configure Shodan key (Live mode)

```bash
cp .env.example .env
```
Edit `.env` and set:
```text
SHODAN_API_KEY=YOUR_REAL_KEY_HERE
```

---

## Run (Sample mode — no API key)

```bash
python ingress.py --use-sample
```
Open:
- `reports/ingress_map_<RUNID>.html`

---

## Run (Live Shodan query)

```bash
python ingress.py --query "port:3389 country:IL" --limit 50
```

---

## Best-effort Attribution (Observed Org)

Ingress can display an **Observed / Inferred Organization** for an asset using **public indicators** such as:

- TLS certificate CN / SAN
- Hostnames / domains returned by Shodan
- HTTP title (very low-confidence hint)

The UI shows an **Attribution Confidence** level and the **Sources** used.

⚠️ This is **not proof of ownership**. Treat it as a triage hint.

---

## Safety / Scope notes

Ingress **does not** exploit vulnerabilities, brute-force, or attempt access.

---
