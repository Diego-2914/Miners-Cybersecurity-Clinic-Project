import csv
import json
from collections import defaultdict
from pathlib import Path


def read_json(path):
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    return json.loads(text)


coverage_path = Path("sboms/openemr-coverage.csv")
grype_path = Path("sboms/openemr-grype.json")
output_path = Path("sboms/openemr-combined-report.csv")

with coverage_path.open(newline="", encoding="utf-8-sig") as f:
    coverage_rows = list(csv.DictReader(f))

grype = read_json(grype_path)

# Group Grype matches by the artifact's exact purl.
matches_by_purl = defaultdict(list)
matches_without_purl = 0

for match in grype.get("matches", []):
    artifact = match.get("artifact") or {}
    purl = artifact.get("purl", "")
    if purl:
        matches_by_purl[purl].append(match)
    else:
        matches_without_purl += 1

fields = [
    "name",
    "version",
    "purl",
    "type",
    "category",
    "reason",
    "grype_match_count",
    "grype_vulnerability_ids",
    "grype_severities",
    "grype_link_status",
]

with output_path.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()

    for row in coverage_rows:
        matches = matches_by_purl.get(row.get("purl", ""), [])

        vuln_ids = sorted({
            (match.get("vulnerability") or {}).get("id", "")
            for match in matches
        } - {""})

        severities = sorted({
            (match.get("vulnerability") or {}).get("severity", "")
            for match in matches
        } - {""})

        writer.writerow({
            **row,
            "grype_match_count": len(matches),
            "grype_vulnerability_ids": "; ".join(vuln_ids),
            "grype_severities": "; ".join(severities),
            "grype_link_status": (
                "matches linked by purl" if matches
                else "no match linked by purl"
            ),
        })

print(f"Wrote {output_path}")
print(f"Grype matches without a purl: {matches_without_purl}")
