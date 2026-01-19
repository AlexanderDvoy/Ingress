from __future__ import annotations
from typing import Any, Dict, List

PATH_TEMPLATES = {
    "RDP": [
        "Exposed remote access service discovered (RDP).",
        "Validate access controls (MFA, network allow-lists, account policies).",
        "If weak controls exist, attacker may attempt credential-based access (Valid Accounts).",
        "Post-access: privilege discovery and lateral movement risks increase.",
    ],
    "SSH": [
        "Exposed remote access service discovered (SSH).",
        "Check for hardened configs (keys-only, allow-lists, MFA where possible).",
        "If weak controls exist, credential-based access becomes plausible.",
        "Post-access: escalation and pivoting become possible depending on host role.",
    ],
    "VPN": [
        "Remote access/VPN exposure discovered.",
        "Review authentication hardening and patch levels.",
        "Compromised remote access can enable entry into internal network segments.",
        "Post-access: internal reconnaissance and movement risks increase.",
    ],
    "WEB_ADMIN": [
        "Public-facing admin/app surface discovered.",
        "Review patch posture and exposed administrative endpoints.",
        "If vulnerable/misconfigured, initial access may occur via public-facing app exposure.",
        "Post-access: session/privilege issues could lead to broader compromise.",
    ],
    "WEB": [
        "Public web service exposure discovered.",
        "Review exposed endpoints and authentication boundaries.",
        "If vulnerabilities exist in public-facing app, initial access becomes plausible.",
        "Post-access: data exposure or pivoting depending on service permissions.",
    ],
    "DB": [
        "Database/service port exposed on the internet.",
        "Confirm access controls, encryption, and network restrictions.",
        "Misconfiguration can lead to unauthorized data access.",
        "Post-access: data theft and credential harvesting risks increase.",
    ],
    "UNKNOWN": [
        "Exposed service discovered.",
        "Identify service purpose and authentication boundary.",
        "Assess whether exposure is required and properly restricted.",
        "Document remediation steps and monitoring coverage.",
    ],
}

MITRE_HINTS = {
    "RDP": ["T1133 (External Remote Services)", "T1078 (Valid Accounts)"],
    "SSH": ["T1133 (External Remote Services)", "T1078 (Valid Accounts)"],
    "VPN": ["T1133 (External Remote Services)"],
    "WEB_ADMIN": ["T1190 (Exploit Public-Facing Application)"],
    "WEB": ["T1190 (Exploit Public-Facing Application)"],
    "DB": ["T1133 (External Remote Services)"],
    "UNKNOWN": [],
}

def build_attack_paths(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []
    for a in assets:
        cat = a.get("category") or "UNKNOWN"
        paths.append({
            "ip": a.get("ip"),
            "port": a.get("port"),
            "category": cat,
            "risk_score": a.get("risk_score"),
            "risk_level": a.get("risk_level"),
            "mitre": MITRE_HINTS.get(cat, []),
            "narrative": PATH_TEMPLATES.get(cat, PATH_TEMPLATES["UNKNOWN"]),
        })
    paths.sort(key=lambda x: int(x.get("risk_score") or 0), reverse=True)
    return paths
