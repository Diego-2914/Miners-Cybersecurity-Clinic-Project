#!/usr/bin/env python3
"""sbom_coverage.py

Reads CycloneDX JSON SBOMs and sorts each software package by whether a
purl-based vulnerability lookup (for example in OSV) could be attempted.

Categories
  Lookup-ready       enough data for this prototype to attempt a lookup
  Insufficient data  something is missing or malformed in the SBOM itself
                     (a possible blind spot for ANY scanner)
  Outside v0 scope   this prototype's rules skip it by design. It says
                     nothing about what Grype or other tools can do.
  Excluded           not a software package (files, OS entry, container)

v0 does NOT query any database. "Lookup-ready" does not mean safe.

Usage
  python sbom_coverage.py sbom.json
  python sbom_coverage.py sbom.json --csv report.csv
  python sbom_coverage.py planted_sbom_v2.json --expected
  python sbom_coverage.py .                       (every .json in this folder)
  python sbom_coverage.py a.json b.json --summary-csv summary.csv
"""
import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter

READY = "Lookup-ready"
INSUFF = "Insufficient data"
SCOPE = "Outside v0 scope"
EXCL = "Excluded"

# Assumptions for v0. Verify against OSV's documented ecosystem list.
LANG_TYPES = {"npm", "pypi", "maven", "golang", "cargo", "nuget",
              "gem", "composer", "hex", "pub"}
OS_TYPES = {"deb", "rpm", "apk", "alpm"}
NON_PACKAGE = {"file", "operating-system", "container", "device", "platform", "data"}


def load(path):
    """Read JSON, tolerating UTF-8 BOMs and the UTF-16 files that older
    Windows PowerShell can produce when output is redirected with '>'."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    return json.loads(text)


def parse_purl(purl):
    """pkg:type/namespace/name@version?qualifiers#subpath -> (type, name, version)"""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#")[0].split("?")[0]
    ptype, _, path = rest.partition("/")
    if not ptype or not path:
        return None
    if "@" in path:
        name, _, version = path.rpartition("@")
    else:
        name, version = path, ""
    return ptype.lower(), name, version


def classify(c):
    """Return (category, reason) for one component."""
    ctype = (c.get("type") or "").lower()
    if ctype in NON_PACKAGE:
        return EXCL, "not a software package (type=%s)" % ctype
    purl = (c.get("purl") or "").strip()
    version_field = (c.get("version") or "").strip()
    cpe = (c.get("cpe") or "").strip()
    if not purl:
        if cpe:
            return SCOPE, "CPE only, no purl (v0 looks up by purl)"
        return INSUFF, "no identifier (no purl or CPE)"
    parsed = parse_purl(purl)
    if parsed is None:
        return INSUFF, "purl could not be parsed"
    ptype, _, purl_version = parsed
    if ptype in OS_TYPES:
        return SCOPE, "OS package (%s)" % ptype
    if ptype not in LANG_TYPES:
        return SCOPE, "purl type '%s' not in v0 ecosystem list" % ptype
    if not purl_version and not version_field:
        return INSUFF, "no version"
    if not purl_version:
        return READY, "version taken from version field (purl has none)"
    return READY, ""


def flatten(components):
    """CycloneDX allows components nested inside components."""
    for c in components or []:
        if isinstance(c, dict):
            yield c
            for sub in flatten(c.get("components")):
                yield sub


def expected_of(c):
    for p in c.get("properties") or []:
        if p.get("name") == "planted:expected":
            return p.get("value", "")
    return None


def analyze(path):
    try:
        bom = load(path)
    except Exception as e:
        return {"path": path, "status": "error",
                "note": "could not read as JSON (%s)" % type(e).__name__}
    if not isinstance(bom, dict):
        return {"path": path, "status": "error", "note": "JSON is not an SBOM object"}
    if bom.get("bomFormat") != "CycloneDX":
        note = "SPDX - not supported in v0" if "spdxVersion" in bom else "not CycloneDX JSON"
        return {"path": path, "status": "unsupported", "note": note}
    comps = list(flatten(bom.get("components")))
    rows = []
    for c in comps:
        cat, reason = classify(c)
        rows.append({"name": c.get("name", ""), "version": c.get("version") or "",
                     "purl": c.get("purl") or "", "type": c.get("type") or "",
                     "category": cat, "reason": reason})
    return {"path": path, "status": "ok", "note": "",
            "spec": bom.get("specVersion", "?"), "comps": comps, "rows": rows}


def counts(rows):
    n = Counter(r["category"] for r in rows)
    pkgs = n[READY] + n[INSUFF] + n[SCOPE]
    return {"packages": pkgs, "ready": n[READY], "insuff": n[INSUFF],
            "scope": n[SCOPE], "excluded": n[EXCL]}


def pct(a, b):
    return (100.0 * a / b) if b else 0.0


def print_detail(res, limit):
    rows, c = res["rows"], counts(res["rows"])
    print("File: %s" % res["path"])
    print("Format: CycloneDX %s | components listed: %d | software packages: %d | excluded: %d"
          % (res["spec"], len(rows), c["packages"], c["excluded"]))
    ex_types = Counter(r["type"] or "(no type)" for r in rows if r["category"] == EXCL)
    if ex_types:
        print("Excluded by type: " + ", ".join("%s=%d" % kv for kv in ex_types.most_common()))
    print()
    print("Lookup-ready: %d | Insufficient data: %d | Outside v0 scope: %d"
          % (c["ready"], c["insuff"], c["scope"]))
    print("Lookup-ready share: %d of %d (%.1f%%)"
          % (c["ready"], c["packages"], pct(c["ready"], c["packages"])))
    print("Insufficient-data share (possible blind spot): %d of %d (%.1f%%)"
          % (c["insuff"], c["packages"], pct(c["insuff"], c["packages"])))
    print("(v0 has not queried any database. Lookup-ready does not mean safe.)")
    print("('Outside v0 scope' reflects this prototype's rules, not what other scanners can do.)")
    bad = [r for r in rows if r["category"] in (INSUFF, SCOPE)]
    if bad:
        print("\nWhy components were not marked lookup-ready:")
        for (cat, reason), n in Counter((r["category"], r["reason"]) for r in bad).most_common():
            print("  %3d  [%s] %s" % (n, cat, reason))
        print("\nFirst %d of those components:" % min(limit, len(bad)))
        for r in bad[:limit]:
            print("  %-30s %-12s %-17s %s"
                  % (r["name"][:30], (r["version"] or "-")[:12], r["category"], r["reason"]))


def print_table(results):
    print("%-32s %-13s %5s %6s %7s %6s %5s %7s"
          % ("File", "Format", "Pkgs", "Ready", "Insuff", "Scope", "Excl", "Ready%"))
    print("-" * 88)
    for r in results:
        name = os.path.basename(r["path"])[:32]
        if r["status"] != "ok":
            print("%-32s %s" % (name, r["note"]))
            continue
        c = counts(r["rows"])
        print("%-32s %-13s %5d %6d %7d %6d %5d %6.1f%%"
              % (name, "CycloneDX " + str(r["spec"]), c["packages"], c["ready"],
                 c["insuff"], c["scope"], c["excluded"], pct(c["ready"], c["packages"])))
    print("\nReady = lookup-ready. Insuff = insufficient data. Scope = outside v0 scope. "
          "Excl = not a software package.")
    print("v0 queries no database. These numbers describe the prototype's rules, "
          "not findings about the software.")


def run_expected(res):
    print("\nPlanted test (expected vs actual):")
    fails = 0
    checked = 0

    for c, r in zip(res["comps"], res["rows"]):
        exp = expected_of(c)
        if exp is None:
            continue

        checked += 1
        exp_cat, _, exp_reason = exp.partition("|")
        good = r["category"] == exp_cat and r["reason"].startswith(exp_reason)
        fails += 0 if good else 1
        print("  %s  %-18s expected=%-42s got=%s"
              % ("PASS" if good else "FAIL", r["name"][:18], exp,
                 r["category"] + ("|" + r["reason"] if r["reason"] else "")))

    if checked == 0:
        print("Planted test: no expected annotations found; nothing was tested.")
        return 1

    print("Planted test: %s" % ("all passed" if fails == 0 else "%d FAILED" % fails))
    return fails


def main():
    ap = argparse.ArgumentParser(description="CycloneDX coverage report (v2)")
    ap.add_argument("paths", nargs="+", help="SBOM files and/or folders of .json files")
    ap.add_argument("--csv", help="single file: write every component and its verdict")
    ap.add_argument("--summary-csv", help="several files: write the summary table")
    ap.add_argument("--limit", type=int, default=20, help="rows to print in the detail list")
    ap.add_argument("--expected", action="store_true",
                    help="single file: compare verdicts with 'planted:expected' properties")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.json")))
        else:
            files.append(p)
    if not files:
        sys.exit("No .json files found.")

    results = [analyze(f) for f in files]

    if len(results) == 1:
        res = results[0]
        if res["status"] != "ok":
            sys.exit("%s: %s" % (res["path"], res["note"]))
        print_detail(res, args.limit)
        if args.csv:
            with open(args.csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["name", "version", "purl", "type",
                                                  "category", "reason"])
                w.writeheader()
                w.writerows(res["rows"])
            print("\nWrote %s" % args.csv)
        if args.expected:
            sys.exit(run_expected(res))
    else:
        if args.expected or args.csv:
            print("Note: --expected and --csv only work with a single file; ignoring them.\n")
        print_table(results)
        if args.summary_csv:
            with open(args.summary_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["file", "status", "format", "packages", "lookup_ready",
                            "insufficient_data", "outside_v0_scope", "excluded",
                            "lookup_ready_pct", "note"])
                for r in results:
                    if r["status"] != "ok":
                        w.writerow([os.path.basename(r["path"]), r["status"], "", "", "", "",
                                    "", "", "", r["note"]])
                    else:
                        c = counts(r["rows"])
                        w.writerow([os.path.basename(r["path"]), "ok",
                                    "CycloneDX " + str(r["spec"]), c["packages"], c["ready"],
                                    c["insuff"], c["scope"], c["excluded"],
                                    "%.1f" % pct(c["ready"], c["packages"]), ""])
            print("\nWrote %s" % args.summary_csv)


if __name__ == "__main__":
    main()
