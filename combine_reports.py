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


# Load the coverage CSV.
with open("coverage.csv", newline="", encoding="utf-8-sig") as f:
    coverage_rows = list(csv.DictReader(f))

# Load Grype's JSON report.
grype = read_json("grype-results.json")

# Group Grype vulnerability matches by the artifact's purl.
matches_by_purl = defaultdict(list)
matches_without_purl = 0

for match in grype.get("matches", []):
    artifact = match.get("artifact") or {}
    purl = artifact.get("purl", "")
    if purl:
        matches_by_purl[purl].append(match)
    else:
        matches_without_purl += 1

# Write a combined report.
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

with open("combined-report.csv", "w", newline="", encoding="utf-8-sig") as f:
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

print("Wrote combined-report.csv")
print(f"Grype matches without a purl: {matches_without_purl}")
