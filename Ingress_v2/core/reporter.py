from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def _top_counts(assets: List[Dict[str, Any]], key: str) -> List[tuple[str, int]]:
    counts: Dict[str, int] = {}
    for a in assets:
        v = str(a.get(key) or "UNKNOWN")
        counts[v] = counts.get(v, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)

def write_markdown_report(path: Path, assets: List[Dict[str, Any]], attack_paths: List[Dict[str, Any]],
                          query: Optional[str], run_id: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    total = len(assets)
    cats = _top_counts(assets, "category")

    lines = []
    lines.append(f"# Ingress Report — {run_id}\n")
    lines.append(f"- Generated (UTC): **{now}**")
    lines.append(f"- Query: `{query or 'SAMPLE DATA'}`")
    lines.append(f"- Total assets: **{total}**\n")

    lines.append("## Category Breakdown\n")
    for c, n in cats:
        lines.append(f"- **{c}**: {n}")
    lines.append("")

    lines.append("## Top Risk Assets (Top 10)\n")
    top = sorted(assets, key=lambda a: int(a.get("risk_score") or 0), reverse=True)[:10]
    lines.append("| Risk | IP | Port | Category | Observed Org | Confidence | Country | Network Owner |")
    lines.append("|---:|---|---:|---|---|---|---|---|")
    for a in top:
        geo = a.get("geo") or {}
        lines.append(
            f"| {a.get('risk_score')} | {a.get('ip')} | {a.get('port')} | {a.get('category')} | "
            f"{a.get('observed_org') or ''} | {a.get('attribution_confidence') or ''} | "
            f"{geo.get('country') or ''} | {a.get('org') or ''} |"
        )
    lines.append("")

    lines.append("## Attack Path Narratives (Top 5)\n")
    for p in attack_paths[:5]:
        lines.append(f"### {p.get('ip')}:{p.get('port')} — {p.get('category')} ({p.get('risk_level')})")
        if p.get("mitre"):
            lines.append(f"- MITRE hints: {', '.join(p['mitre'])}")
        lines.append("- Narrative:")
        for step in p.get("narrative") or []:
            lines.append(f"  - {step}")
        lines.append("")

    lines.append("## Notes\n")
    lines.append("- This output is intended for **authorized security assessments** and defensive triage.")
    lines.append("- No exploitation is performed by this tool.")
    lines.append("- Observed Org attribution is **best-effort** and not ownership proof.\n")

    path.write_text("\n".join(lines), encoding="utf-8")
