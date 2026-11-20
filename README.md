# SBOM Blind Spot Scanner

## What it is

SBOM Blind Spot Scanner gives visibility into the components that make up a piece of software a business is considering bringing in-house. A user supplies an existing CycloneDX SBOM — from Syft or any other tool that can produce one — and the pipeline checks each component for known vulnerabilities using Grype, while independently judging whether every component in that inventory could actually be identified and checked in the first place. The two results are joined into a single report that shows not just what was found, but where the picture is incomplete — turning a long list of parts into a clear picture of what's covered and what isn't.

## Who it's for

Anyone evaluating a piece of third-party or open-source software before bringing it into their business — an IT or security reviewer, or someone responsible for approving new software before it's brought in — who wants to know where known vulnerabilities sit and where visibility runs out before committing to that software. The reporting is written in plain language, so the result is useful to the person making the decision, not only to someone already fluent in security tooling.

## Where it's heading

A local tool that lets a user submit their own SBOM directly — instead of browsing fixed examples — has been written and has passed extensive testing; final verification on live hardware is in progress. The near-term goal is finishing that into this project's public GitHub repository as a working deliverable. Beyond that, the next real expansion is removing the last manual step entirely: letting someone simply name a piece of software they're considering — a repository or a container image — and have the tool generate its SBOM automatically, so no one needs to already have one in hand to use it.

## Try it

```
python server.py
```

Then open **http://127.0.0.1:8000** and upload a CycloneDX JSON SBOM. The page runs the full pipeline (Grype → coverage classification → combine) and shows the result as a dashboard. Nothing you upload is kept — each upload runs in its own temporary folder, deleted once the result is shown.

Requires [Grype](https://github.com/anchore/grype) installed and on your PATH. No other dependencies — everything here is Python's standard library.

## Run it from the command line

```
python run_pipeline.py --sbom path/to/sbom.json --outdir pipeline-out
python build_dashboard.py --outdir pipeline-out --title "My software" --out dashboard.html
```

## How it works

1. **Grype** scans the SBOM against its vulnerability database.
2. **`sbom_coverage.py`** independently classifies every component in the SBOM by whether it could even be identified well enough to look up — this step queries no database. Its categories:
   - **Lookup-ready** — identified clearly enough to attempt a lookup.
   - **Insufficient data** — the SBOM itself is missing something (no scanner could judge this one).
   - **Outside v0 scope** — outside this prototype's purl-based rules (an OS package, for example). This does *not* mean unchecked — Grype may have covered it anyway.
   - **Excluded** — not a software package (a dependency lock file, an OS entry).
3. **`combine.py`** joins the two by exact package URL into one report, and counts anything that didn't link — the gap between "Grype found something" and "we could tie it to a component."
4. **`build_dashboard.py`** renders that report as a standalone dashboard, with a panel that distinguishes genuine blind spots from components merely outside this tool's current rules.

## What this doesn't claim to be

This is an educational visibility and reporting aid, not a security certification. "Lookup-ready" means a lookup could be attempted, not that a component is safe. No known vulnerability found is not proof a component is safe — matches are joined by exact package URL, so a formatting difference could hide one. It's one snapshot: one tool version, one vulnerability database date, one copy of the source.

## Repository layout

- `run_pipeline.py` — runs Grype, coverage, and combine from one command.
- `sbom_coverage.py` — classifies components by whether they can be checked.
- `combine.py` — joins coverage results with Grype's findings by purl.
- `build_dashboard.py` — generates the dashboard from a pipeline run.
- `server.py` — local web page for uploading an SBOM and getting the dashboard back.
- `sbom-dashboard.html` — the OpenEMR / illustrative-example dashboard built so far.
- `sboms/` — example SBOMs and scan results, including the tests used to verify the pipeline (SBOM-input vs. directory-input comparison, scoped-npm and Composer ecosystem checks).
