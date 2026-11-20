#!/usr/bin/env python3
"""combine.py -- join a coverage CSV with Grype's JSON results by exact purl.

Replaces combine_reports.py and combine_reports_openemr.py, which were the
same logic with different hard-coded file names. This one takes paths as
arguments, so it works for any project.

  python combine.py --coverage coverage.csv --grype grype.json --out combined-report.csv

It can also be imported:  from combine import combine
"""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

FIELDS = ["name", "version", "purl", "type", "category", "reason",
          "grype_match_count", "grype_vulnerability_ids",
          "grype_severities", "grype_link_status"]

COVERAGE_FIELDS = ["name", "version", "purl", "type", "category", "reason"]


def read_json(path):
    """Read JSON, tolerating a UTF-8 BOM or the UTF-16 a redirected
    PowerShell '>' can produce -- same rule the other scripts use."""
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    return json.loads(text)


def index_matches(grype):
    """Group Grype matches by the artifact's exact purl, and count the
    matches that have no purl (a match the join cannot attach to anything)."""
    by_purl = defaultdict(list)
    without_purl = 0
    for match in grype.get("matches", []):
        purl = (match.get("artifact") or {}).get("purl", "")
        if purl:
            by_purl[purl].append(match)
        else:
            without_purl += 1
    return by_purl, without_purl


def combine(coverage_csv, grype_json, out_csv):
    """Join coverage rows to Grype matches by exact purl. Returns a small
    stats dict so the caller can report what the join did."""
    with open(coverage_csv, newline="", encoding="utf-8-sig") as f:
        coverage_rows = list(csv.DictReader(f))

    grype = read_json(grype_json)
    by_purl, without_purl = index_matches(grype)

    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in coverage_rows:
            matches = by_purl.get(row.get("purl", ""), [])
            vuln_ids = sorted({(m.get("vulnerability") or {}).get("id", "")
                               for m in matches} - {""})
            severities = sorted({(m.get("vulnerability") or {}).get("severity", "")
                                 for m in matches} - {""})
            out = {k: row.get(k, "") for k in COVERAGE_FIELDS}
            out.update({
                "grype_match_count": len(matches),
                "grype_vulnerability_ids": "; ".join(vuln_ids),
                "grype_severities": "; ".join(severities),
                "grype_link_status": ("matches linked by purl" if matches
                                      else "no match linked by purl"),
            })
            writer.writerow(out)

    linked = sum(len(v) for v in by_purl.values())
    return {"coverage_rows": len(coverage_rows),
            "linked_matches": linked,
            "matches_without_purl": without_purl}


def main():
    ap = argparse.ArgumentParser(
        description="Join a coverage CSV with Grype JSON results by exact purl.")
    ap.add_argument("--coverage", required=True, help="coverage CSV from sbom_coverage.py")
    ap.add_argument("--grype", required=True, help="Grype JSON results")
    ap.add_argument("--out", required=True, help="combined report CSV to write")
    args = ap.parse_args()

    stats = combine(args.coverage, args.grype, args.out)
    print("Wrote %s" % args.out)
    print("Coverage rows: %d | Grype matches linked by purl: %d | matches without a purl: %d"
          % (stats["coverage_rows"], stats["linked_matches"], stats["matches_without_purl"]))


if __name__ == "__main__":
    main()
