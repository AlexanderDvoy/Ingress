Ingress
Shodan-Driven Initial Access & Attack Surface Mapping Tool

Ingress is an offensive-minded security research tool designed to model how real-world attacks begin — by identifying and prioritizing Initial Access vectors exposed on the public internet.

Instead of focusing on exploitation, Ingress focuses on attacker decision-making:

If I were the attacker — where would I try to break in first?

🚨 Disclaimer

For authorized security assessments only.
Ingress performs no exploitation, brute force, or active scanning.
It only analyzes publicly available data (e.g. Shodan) for defensive and research purposes.

Use this tool only on assets you own or have explicit permission to assess.

✨ Features

🔍 Collects exposed services using Shodan

🎯 Classifies Initial Access vectors (RDP, SSH, VPN, Web Admin, etc.)

📊 Calculates risk scores and severity levels

🧭 Maps findings to MITRE ATT&CK techniques

🏢 Performs best-effort organization attribution (non-assertive)

🗺️ Renders a real interactive world map (HTML) of exposed assets

📄 Generates structured JSON + Markdown reports

🧪 Safe demo mode (no API key required)

🧠 Why Ingress?

Most breaches don’t start with zero-days or advanced payloads.
They start with something simple that was left exposed:

Open RDP

Legacy SSH

Public VPN portals

Forgotten admin panels

Ingress visualizes these entry points the way a Red Team or attacker would think about them, while remaining fully non-intrusive.

📦 Output Artifacts

Each run generates the following files in reports/:

File	Description
assets_<RUNID>.json	Normalized Shodan asset data
attack_paths_<RUNID>.json	Descriptive attack-path narratives
report_<RUNID>.md	Human-readable Markdown report
ingress_map_<RUNID>.html	Interactive attack surface map
🗺️ Map Visualization

Each marker on the map represents a potential Initial Access point, including:

IP & Port

Service category

Risk score & severity

MITRE ATT&CK technique

Network owner (ASN / ISP)

Observed organization (best-effort)

Attribution confidence & sources

Geographic location

Marker colors:

🔴 High risk

🟠 Medium risk

🟢 Low risk

🏢 Best-Effort Attribution (Observed Org)

Ingress may display an Observed / Inferred Organization, based on public indicators such as:

TLS certificate CN / SAN

Hostnames or domains

HTTP titles (low confidence)

Each attribution includes:

Confidence level (Low / Medium / High)

Source indicators

Clear labeling as best-effort, not ownership proof

⚠️ Attribution is intentionally conservative to avoid false claims.

🛠️ Installation
Requirements

Python 3.10+

Shodan API key (for live mode)

Setup (Linux / macOS)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Setup (Windows PowerShell)
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

▶️ Usage
1️⃣ Demo mode (no API key)
python ingress.py --use-sample


Open the generated map:

reports/ingress_map_<RUNID>.html

2️⃣ Live mode (Shodan)

Create .env:

cp .env.example .env


Edit .env:

SHODAN_API_KEY=YOUR_REAL_KEY_HERE


Run:

python ingress.py --query "port:3389 country:IL" --limit 50

🔍 Example Queries
port:3389 country:IL
asn:AS12345
(org:"ExampleCorp") (port:22 OR port:443)


⚠️ API limits depend on your Shodan plan.

🧱 Project Structure
Ingress/
├── ingress.py
├── core/
│   ├── shodan_collector.py
│   ├── asset_classifier.py
│   ├── attribution.py
│   ├── risk_engine.py
│   ├── attack_path_generator.py
│   └── reporter.py
├── geo/
│   └── attack_map.py
├── data/
│   ├── sample_assets.json
│   └── mitre_mapping.yaml
├── reports/
├── requirements.txt
├── .env.example
└── README.md

🛡️ Safety & Design Principles

❌ No exploitation

❌ No scanning

❌ No credential testing

✅ Public data only

✅ Attribution is non-assertive

✅ Designed for education, research & defense
