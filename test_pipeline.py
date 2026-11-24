#!/usr/bin/env python3
"""test_pipeline.py -- automated tests for the SBOM Blind Spot Scanner.

Run from the project folder:

    python -m unittest test_pipeline -v
    python test_pipeline.py          (same thing)

Uses only Python's standard library -- no pytest, nothing to install.
These tests do not run Grype: they feed the pipeline Grype output
directly, so the whole suite runs anywhere Python does, in a second or
two. The one thing they deliberately do not cover is a live Grype scan
on real hardware; that is the manual end-to-end check.

What is covered
  - Input validation: empty / malformed / wrong-format / non-CycloneDX files
  - Coverage classification: every category and the reasons behind them
  - The purl join: duplicate purls, matches with no purl, zero matches
  - The full run() orchestration, via an existing Grype result
  - Dashboard generation, including the blind-spot split that separates
    "nothing could identify this" from "outside this tool's rules, but
    Grype may have checked it anyway"
"""
import csv
import json
import tempfile
import unittest
from pathlib import Path

import run_pipeline
import sbom_coverage
import combine
import build_dashboard


def write(path, text):
    Path(path).write_text(text, encoding="utf-8")


# A small CycloneDX SBOM exercising one component of each kind we care about.
SAMPLE_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "components": [
        # lookup-ready: recognized ecosystem + version
        {"type": "library", "name": "jszip", "version": "3.2.2",
         "purl": "pkg:npm/jszip@3.2.2"},
        {"type": "library", "name": "guzzlehttp/guzzle", "version": "6.5.5",
         "purl": "pkg:composer/guzzlehttp/guzzle@6.5.5"},
        # insufficient data: no version anywhere
        {"type": "library", "name": "chart.js", "purl": "pkg:npm/chart.js"},
        # insufficient data: no identifier at all
        {"type": "library", "name": "vendor-blob", "version": "1.0"},
        # insufficient data: unparseable purl
        {"type": "library", "name": "legacy", "version": "1.0",
         "purl": "not-a-real-purl"},
        # outside scope: OS package
        {"type": "library", "name": "openssl", "version": "1.1.1n",
         "purl": "pkg:deb/debian/openssl@1.1.1n"},
        # outside scope: CPE only, no purl
        {"type": "library", "name": "proprietary", "version": "4.1",
         "cpe": "cpe:2.3:a:vendor:proprietary:4.1:*:*:*:*:*:*:*"},
        # excluded: not a software package
        {"type": "file", "name": "package-lock.json"},
    ],
}


class TestValidation(unittest.TestCase):
    """validate_sbom_bytes is the gate the web upload relies on to turn
    bad input into a clean message instead of a crash."""

    def test_valid_sbom_passes(self):
        run_pipeline.validate_sbom_bytes(json.dumps(SAMPLE_SBOM))  # no raise

    def test_empty_file(self):
        with self.assertRaises(run_pipeline.PipelineError) as cm:
            run_pipeline.validate_sbom_bytes("")
        self.assertIn("empty", str(cm.exception).lower())

    def test_malformed_json(self):
        with self.assertRaises(run_pipeline.PipelineError) as cm:
            run_pipeline.validate_sbom_bytes('{"bomFormat": "CycloneDX", oops')
        self.assertIn("valid json", str(cm.exception).lower())

    def test_json_but_not_object(self):
        with self.assertRaises(run_pipeline.PipelineError):
            run_pipeline.validate_sbom_bytes('[1, 2, 3]')

    def test_missing_bomformat(self):
        with self.assertRaises(run_pipeline.PipelineError) as cm:
            run_pipeline.validate_sbom_bytes('{"hello": "world"}')
        self.assertIn("bomformat", str(cm.exception).lower())

    def test_wrong_bomformat_spdx(self):
        with self.assertRaises(run_pipeline.PipelineError) as cm:
            run_pipeline.validate_sbom_bytes('{"bomFormat": "SPDX", "components": []}')
        self.assertIn("cyclonedx", str(cm.exception).lower())

    def test_cyclonedx_without_components(self):
        with self.assertRaises(run_pipeline.PipelineError) as cm:
            run_pipeline.validate_sbom_bytes('{"bomFormat": "CycloneDX"}')
        self.assertIn("components", str(cm.exception).lower())


class TestClassification(unittest.TestCase):
    """sbom_coverage.classify is where a component is judged checkable or
    not. These pin the category AND the reason for each kind."""

    def cat(self, component):
        return sbom_coverage.classify(component)

    def test_lookup_ready_npm(self):
        c, _ = self.cat({"type": "library", "purl": "pkg:npm/jszip@3.2.2"})
        self.assertEqual(c, sbom_coverage.READY)

    def test_lookup_ready_scoped_npm(self):
        # URL-encoded scoped package -- must not be mistaken for malformed
        c, _ = self.cat({"type": "library",
                         "purl": "pkg:npm/%40babel/traverse@7.22.5"})
        self.assertEqual(c, sbom_coverage.READY)

    def test_composer_is_lookup_ready(self):
        c, _ = self.cat({"type": "library",
                         "purl": "pkg:composer/guzzlehttp/guzzle@6.5.5"})
        self.assertEqual(c, sbom_coverage.READY)

    def test_no_version_is_insufficient(self):
        c, r = self.cat({"type": "library", "purl": "pkg:npm/chart.js"})
        self.assertEqual(c, sbom_coverage.INSUFF)
        self.assertIn("version", r.lower())

    def test_no_identifier_is_insufficient(self):
        c, r = self.cat({"type": "library", "name": "blob", "version": "1.0"})
        self.assertEqual(c, sbom_coverage.INSUFF)

    def test_unparseable_purl_is_insufficient(self):
        c, _ = self.cat({"type": "library", "purl": "not-a-purl"})
        self.assertEqual(c, sbom_coverage.INSUFF)

    def test_os_package_is_outside_scope(self):
        c, _ = self.cat({"type": "library",
                         "purl": "pkg:deb/debian/openssl@1.1.1n"})
        self.assertEqual(c, sbom_coverage.SCOPE)

    def test_cpe_only_is_outside_scope(self):
        c, _ = self.cat({"type": "library", "version": "4.1",
                         "cpe": "cpe:2.3:a:v:p:4.1:*:*:*:*:*:*:*"})
        self.assertEqual(c, sbom_coverage.SCOPE)

    def test_unknown_ecosystem_is_outside_scope(self):
        c, _ = self.cat({"type": "library", "purl": "pkg:generic/thing@1.0"})
        self.assertEqual(c, sbom_coverage.SCOPE)

    def test_file_is_excluded(self):
        c, _ = self.cat({"type": "file", "name": "package-lock.json"})
        self.assertEqual(c, sbom_coverage.EXCL)

    def test_operating_system_is_excluded(self):
        c, _ = self.cat({"type": "operating-system", "name": "debian"})
        self.assertEqual(c, sbom_coverage.EXCL)


class TestCombine(unittest.TestCase):
    """combine joins coverage rows to Grype matches by exact purl and must
    account for every match -- especially ones it cannot attach."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cov = self.tmp / "coverage.csv"
        with open(self.cov, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["name", "version", "purl",
                                              "type", "category", "reason"])
            w.writeheader()
            w.writerow({"name": "jszip", "version": "3.2.2",
                        "purl": "pkg:npm/jszip@3.2.2", "type": "library",
                        "category": "Lookup-ready", "reason": ""})
            w.writerow({"name": "jszip-dup", "version": "3.2.2",
                        "purl": "pkg:npm/jszip@3.2.2", "type": "library",
                        "category": "Lookup-ready", "reason": ""})

    def _grype(self, matches):
        p = self.tmp / "grype.json"
        p.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        return p

    def test_match_links_to_component(self):
        g = self._grype([{"artifact": {"purl": "pkg:npm/jszip@3.2.2"},
                          "vulnerability": {"id": "GHSA-x", "severity": "Medium"}}])
        out = self.tmp / "out.csv"
        stats = combine.combine(str(self.cov), str(g), str(out))
        self.assertEqual(stats["matches_without_purl"], 0)
        with open(out, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        # both duplicate-purl components get the match attached
        for row in rows:
            self.assertEqual(row["grype_match_count"], "1")
            self.assertIn("GHSA-x", row["grype_vulnerability_ids"])

    def test_match_without_purl_is_counted(self):
        g = self._grype([
            {"artifact": {"purl": "pkg:npm/jszip@3.2.2"},
             "vulnerability": {"id": "GHSA-x", "severity": "Medium"}},
            {"artifact": {"purl": ""},  # a finding the join cannot attach
             "vulnerability": {"id": "GHSA-orphan", "severity": "High"}},
        ])
        out = self.tmp / "out.csv"
        stats = combine.combine(str(self.cov), str(g), str(out))
        self.assertEqual(stats["matches_without_purl"], 1)

    def test_zero_matches(self):
        g = self._grype([])
        out = self.tmp / "out.csv"
        stats = combine.combine(str(self.cov), str(g), str(out))
        self.assertEqual(stats["linked_matches"], 0)
        self.assertEqual(stats["matches_without_purl"], 0)


class TestRunAndDashboard(unittest.TestCase):
    """The whole pipeline via run(), fed an existing Grype result, and the
    dashboard built from it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.sbom = self.tmp / "sbom.json"
        self.sbom.write_text(json.dumps(SAMPLE_SBOM), encoding="utf-8")
        # Grype result: a normal npm match, PLUS a match on an OS package
        # that coverage marks "outside scope" -- the case that proves
        # "outside scope" does not mean "unchecked".
        self.grype = self.tmp / "grype.json"
        self.grype.write_text(json.dumps({
            "matches": [
                {"artifact": {"purl": "pkg:npm/jszip@3.2.2"},
                 "vulnerability": {"id": "GHSA-js", "severity": "Medium"}},
                {"artifact": {"purl": "pkg:deb/debian/openssl@1.1.1n"},
                 "vulnerability": {"id": "CVE-OPENSSL", "severity": "Critical"}},
            ],
            "descriptor": {"version": "0.121.1-test",
                           "db": {"status": {"built": "2026-11-20T00:00:00Z"}},
                           "timestamp": "2026-11-20T00:00:00Z"},
            "source": {"type": "sbom-file", "target": "sbom.json"},
        }), encoding="utf-8")

    def test_run_produces_all_outputs(self):
        outdir = self.tmp / "out"
        r = run_pipeline.run(self.sbom, outdir, grype_json_path=self.grype)
        for key in ("grype_json", "coverage_csv", "combined_csv"):
            self.assertTrue(Path(r[key]).is_file(), "%s not written" % key)

    def test_run_counts_match_expectations(self):
        outdir = self.tmp / "out"
        r = run_pipeline.run(self.sbom, outdir, grype_json_path=self.grype)
        # 8 components: 2 ready, 3 insufficient, 2 outside scope, 1 excluded
        self.assertEqual(r["total"], 8)
        self.assertEqual(r["ready"], 2)
        self.assertEqual(r["insuff"], 3)
        self.assertEqual(r["scope"], 2)
        self.assertEqual(r["excluded"], 1)
        self.assertEqual(r["linked_matches"], 2)
        self.assertEqual(r["matches_without_purl"], 0)

    def test_missing_sbom_raises(self):
        with self.assertRaises(run_pipeline.PipelineError):
            run_pipeline.run(self.tmp / "does-not-exist.json", self.tmp / "o")

    def test_dashboard_builds_and_splits_blind_spots(self):
        outdir = self.tmp / "out"
        run_pipeline.run(self.sbom, outdir, grype_json_path=self.grype)
        html = build_dashboard.build(outdir, "Test software")
        # the dashboard embeds its data; confirm the key distinctions render
        self.assertIn("Not identifiable", html)
        self.assertIn("Outside this prototype's lookup rules", html)
        # the openssl match is the proof that "outside scope" != "unchecked"
        self.assertIn("matches found anyway", html)
        self.assertIn("CVE-OPENSSL", html)

    def test_dashboard_provenance_from_grype(self):
        outdir = self.tmp / "out"
        run_pipeline.run(self.sbom, outdir, grype_json_path=self.grype)
        html = build_dashboard.build(outdir, "Test software")
        # provenance is read from Grype's own output, not typed by hand
        self.assertIn("0.121.1-test", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
