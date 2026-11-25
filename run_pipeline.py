#!/usr/bin/env python3
"""run_pipeline.py -- one command: an SBOM in, coverage + combined report out.

  python run_pipeline.py --sbom sbom.json --outdir results
  python run_pipeline.py --sbom sbom.json --grype-json existing-grype.json --outdir results

Steps
  1. Grype scans the SBOM for known vulnerabilities
     (skipped when --grype-json points at a Grype result you already have).
  2. sbom_coverage sorts each component by whether it could be looked up.
  3. combine joins the two by exact purl into one report.

Reuses sbom_coverage.py and combine.py unchanged; installs nothing.
When it runs Grype itself, Grype must be on PATH -- same as the manual
pipeline today. The user never needs Syft: they bring the SBOM.

This module is import-safe: every failure raises PipelineError instead of
calling sys.exit, so a caller (a web server, a test) can catch it and show
a clean message instead of the whole process dying. Only __main__ turns a
PipelineError into a process exit.
"""
import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import sbom_coverage as cov
import combine as combine_mod

COV_FIELDS = ["name", "version", "purl", "type", "category", "reason"]


class PipelineError(Exception):
    """A problem the caller should show to the user, not a crash."""
    pass


def validate_sbom_bytes(data):
    """Check that this looks like a CycloneDX JSON SBOM before anything
    runs Grype on it. Raises PipelineError with a message meant to be
    shown directly to the person who uploaded the file -- this is what
    turns 'malformed JSON' and 'wrong format' into a clean message
    instead of a confusing Grype error several steps downstream."""
    if not data or not data.strip():
        raise PipelineError("The file is empty.")
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as e:
        raise PipelineError(
            "This isn't valid JSON (%s at line %d, column %d). "
            "SBOMs from this tool must be CycloneDX JSON." % (e.msg, e.lineno, e.colno))
    if not isinstance(obj, dict):
        raise PipelineError("This is valid JSON, but not a CycloneDX SBOM "
                            "(the top level must be an object, not a %s)."
                            % type(obj).__name__)
    fmt = obj.get("bomFormat")
    if fmt is None:
        raise PipelineError(
            "This JSON file has no \"bomFormat\" field, so it doesn't look like "
            "a CycloneDX SBOM. If you have SPDX or another format, convert it to "
            "CycloneDX JSON first (Syft can export either format).")
    if fmt != "CycloneDX":
        raise PipelineError(
            "This file's bomFormat is \"%s\", not \"CycloneDX\". "
            "This tool only reads CycloneDX JSON SBOMs." % fmt)
    if "components" not in obj:
        raise PipelineError(
            "This CycloneDX file has no \"components\" list, so there is nothing "
            "to analyze.")
    return obj


def run_grype(sbom_path, out_json):
    exe = shutil.which("grype")
    if not exe:
        raise PipelineError(
            "Grype is not installed or not on PATH. Install Grype, or pass "
            "a Grype result you already have.")
    # Arguments are passed as a list (no shell), so an unusual file name
    # cannot be turned into a shell command.
    #
    # Capture raw bytes, not text. Grype emits UTF-8 JSON; letting Python
    # decode it through the console code page (cp1252 on Windows) throws
    # UnicodeDecodeError on bytes that code page has no character for.
    #
    # Turn OFF Grype's per-run database auto-update: that download can take
    # far longer than the scan itself and would hang a web request waiting
    # on the network. The vulnerability database is refreshed deliberately
    # with `grype db update` (see the README), and its build date is recorded
    # in each report's provenance. A scan uses whatever database is already
    # present, so scans are fast and predictable.
    env = dict(os.environ)
    env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
    try:
        proc = subprocess.run([exe, "sbom:" + str(sbom_path), "-o", "json"],
                              capture_output=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        raise PipelineError(
            "Grype did not finish within 3 minutes. If this is the first scan "
            "in a while, its vulnerability database may need refreshing -- run "
            "`grype db update` once in a terminal, then try again.")
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        hint = ""
        if "database" in detail.lower() or "no db" in detail.lower():
            hint = "  (Try running `grype db update` once in a terminal.)"
        raise PipelineError("Grype failed (exit %d).%s%s"
                            % (proc.returncode, (" " + detail) if detail else "", hint))
    data = proc.stdout or b""
    if not data.strip():
        raise PipelineError("Grype ran but produced no output.")
    Path(out_json).write_bytes(data)


def write_coverage(sbom_path, out_csv):
    res = cov.analyze(str(sbom_path))
    if res["status"] != "ok":
        raise PipelineError("Coverage step could not read the SBOM: %s" % res["note"])
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COV_FIELDS)
        w.writeheader()
        w.writerows(res["rows"])
    return cov.counts(res["rows"])


def run(sbom_path, outdir, grype_json_path=None):
    """Run the full pipeline. Raises PipelineError on any handled failure.
    Returns a dict with the output paths and summary counts."""
    sbom_path = Path(sbom_path)
    if not sbom_path.is_file():
        raise PipelineError("SBOM not found: %s" % sbom_path)

    validate_sbom_bytes(sbom_path.read_text(encoding="utf-8-sig", errors="replace"))

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    grype_json = outdir / "grype.json"
    coverage_csv = outdir / "coverage.csv"
    combined_csv = outdir / "combined-report.csv"

    used_existing_grype = False
    if grype_json_path:
        src = Path(grype_json_path)
        if not src.is_file():
            raise PipelineError("--grype-json file not found: %s" % src)
        grype_json.write_bytes(src.read_bytes())
        used_existing_grype = True
    else:
        run_grype(sbom_path, grype_json)

    counts = write_coverage(sbom_path, coverage_csv)
    stats = combine_mod.combine(str(coverage_csv), str(grype_json), str(combined_csv))

    total = counts["packages"] + counts["excluded"]
    return {
        "grype_json": grype_json, "coverage_csv": coverage_csv,
        "combined_csv": combined_csv, "used_existing_grype": used_existing_grype,
        "total": total, "ready": counts["ready"], "insuff": counts["insuff"],
        "scope": counts["scope"], "excluded": counts["excluded"],
        "linked_matches": stats["linked_matches"],
        "matches_without_purl": stats["matches_without_purl"],
    }


def main():
    ap = argparse.ArgumentParser(
        description="Run the full SBOM coverage pipeline from a single SBOM file.")
    ap.add_argument("--sbom", required=True, help="CycloneDX JSON SBOM to analyze")
    ap.add_argument("--outdir", default="pipeline-out", help="folder for output files")
    ap.add_argument("--grype-json",
                    help="use this existing Grype JSON instead of running Grype")
    args = ap.parse_args()

    try:
        if not args.grype_json:
            print("1/3  Grype scanning %s ..." % Path(args.sbom).name)
        else:
            print("1/3  Using existing Grype results: %s" % Path(args.grype_json).name)
        print("2/3  Classifying components (coverage) ...")
        print("3/3  Joining coverage with Grype results ...")
        r = run(args.sbom, args.outdir, args.grype_json)
    except PipelineError as e:
        sys.exit(str(e))

    print()
    print("Done. Wrote:")
    for p in (r["grype_json"], r["coverage_csv"], r["combined_csv"]):
        print("  %s" % p)
    print()
    print("Components listed: %d  (lookup-ready %d | insufficient %d | outside scope %d | excluded %d)"
          % (r["total"], r["ready"], r["insuff"], r["scope"], r["excluded"]))
    print("Grype matches linked by purl: %d | matches without a purl: %d"
          % (r["linked_matches"], r["matches_without_purl"]))


if __name__ == "__main__":
    main()
