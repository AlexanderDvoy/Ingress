#!/usr/bin/env python3
"""
Ingress — Shodan-Driven Initial Access & Attack Surface Mapper
--------------------------------------------------------------
This tool is for authorized security testing and defensive assessment ONLY.
Use it only on assets you own or have explicit written permission to test.
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from core.shodan_collector import collect_shodan_assets
from core.asset_classifier import classify_assets
from core.attribution import infer_organization
from core.risk_engine import score_assets
from core.attack_path_generator import build_attack_paths
from core.reporter import write_markdown_report, write_json
from geo.attack_map import build_attack_map


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ingress",
        description="Collect internet-exposed services from Shodan, classify initial-access vectors, score risk, and render an interactive map."
    )
    p.add_argument("--query", required=False, default=None,
                   help='Shodan query (e.g. \'port:3389 org:"Example" country:IL\')')
    p.add_argument("--limit", type=int, default=50, help="Max results to fetch (default: 50)")
    p.add_argument("--outdir", default="reports", help="Output directory (default: reports)")
    p.add_argument("--use-sample", action="store_true",
                   help="Run with bundled sample data (no Shodan API required). Good for demos.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if args.use_sample:
        sample_path = Path(__file__).resolve().parent / "data" / "sample_assets.json"
        assets = json.loads(sample_path.read_text(encoding="utf-8"))
    else:
        if not args.query:
            raise SystemExit("Error: --query is required unless you use --use-sample.")
        assets = collect_shodan_assets(args.query, limit=args.limit)

    assets = classify_assets(assets)

    # Best-effort organization attribution (observed/inferred)
    for asset in assets:
        attribution = infer_organization(asset)
        asset.update(attribution)
        if attribution.get("observed_org"):
            asset["attribution_note"] = "Best-effort, based on public indicators"

    assets = score_assets(assets)
    attack_paths = build_attack_paths(assets)

    # Write artifacts
    assets_json = outdir / f"assets_{run_id}.json"
    paths_json = outdir / f"attack_paths_{run_id}.json"
    report_md = outdir / f"report_{run_id}.md"
    map_html = outdir / f"ingress_map_{run_id}.html"

    write_json(assets_json, assets)
    write_json(paths_json, attack_paths)
    write_markdown_report(report_md, assets, attack_paths, query=args.query, run_id=run_id)

    build_attack_map(map_html, assets, title=f"Ingress Map • {run_id}")

    print("\n✅ Done! Generated:")
    print(f" - {assets_json}")
    print(f" - {paths_json}")
    print(f" - {report_md}")
    print(f" - {map_html}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
