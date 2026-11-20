#!/usr/bin/env python3
"""build_dashboard.py -- turn one pipeline-out folder into a standalone
dashboard page. Supersedes make_dashboard.py.

  python build_dashboard.py --outdir pipeline-out --title "OpenEMR" --out dashboard.html

Reads coverage.csv (via combined-report.csv, which already carries every
coverage field) and grype.json from --outdir. No build step, no
dependencies -- the output is one HTML file you open directly.

Also usable as a library:
    from build_dashboard import build
    html = build(outdir, title, note=None, provenance=None)
"""
import argparse
import html as htmlmod
import json
from collections import defaultdict
from pathlib import Path

READY = "Lookup-ready"
INSUFF = "Insufficient data"
SCOPE = "Outside v0 scope"
EXCL = "Excluded"
ORDER = [READY, INSUFF, SCOPE, EXCL]


def read_json(path):
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig"))


def load_rows(combined_csv):
    import csv
    with open(combined_csv, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        try:
            count = int(r.get("grype_match_count") or 0)
        except ValueError:
            count = 0
        out.append({
            "name": r.get("name", ""), "version": r.get("version", ""),
            "purl": r.get("purl", ""), "type": r.get("type", ""),
            "category": r.get("category", ""), "reason": r.get("reason", ""),
            "count": count, "ids": r.get("grype_vulnerability_ids", ""),
            "sev": r.get("grype_severities", ""), "link": r.get("grype_link_status", ""),
        })
    return out


def unlinked_count(grype_json_path):
    """Grype matches that carry no purl -- the join cannot attach these to
    any component, so they are a real blind spot, not a clean result."""
    data = read_json(grype_json_path)
    return sum(1 for m in data.get("matches", [])
              if not (m.get("artifact") or {}).get("purl", ""))


def grype_descriptor(grype_json_path):
    """Pull reproducibility facts straight from Grype's own output, rather
    than typing them in by hand."""
    data = read_json(grype_json_path)
    desc = data.get("descriptor", {}) or {}
    db = (desc.get("db") or {})
    status = db.get("status", db) if isinstance(db, dict) else {}
    return {
        "grype_version": desc.get("version", ""),
        "db_built": status.get("built", ""),
        "db_schema": status.get("schemaVersion", ""),
        "scan_timestamp": desc.get("timestamp", ""),
        "source_type": (data.get("source") or {}).get("type", ""),
        "source_target": (data.get("source") or {}).get("target", ""),
    }


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__ - SBOM coverage</title>
<style>
:root{--teal:#157A6E;--amber:#B7650B;--slate:#55636F;--red:#B83A4B;--ink:#1f2d33}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff}
main{max-width:980px;margin:0 auto;padding:28px 20px 70px}
h1{font-size:1.7rem;margin:0 0 6px}
h2{font-size:1.25rem;margin:34px 0 10px;border-bottom:2px solid #EDEDED;padding-bottom:6px}
.lede{color:var(--slate);margin:0 0 4px}
.muted{color:var(--slate);font-size:.9rem}
.banner{margin:16px 0 4px;padding:12px 16px;border-radius:8px;border-left:5px solid var(--amber);background:#FBF1E4;font-size:.95rem}
.banner b{display:block;margin-bottom:3px}
.stats{display:flex;flex-wrap:wrap;gap:22px;margin:14px 0 2px}
.stat{display:flex;flex-direction:column}
.stat .big{font-size:1.6rem;font-weight:700;line-height:1.1}
.stat .l{font-size:.82rem;color:var(--slate)}
.cov-head{font-size:1.02rem;margin:0 0 10px;font-weight:600}
.bar{display:flex;height:17px;border-radius:4px;overflow:hidden;background:#F0F0F0}
.bar i{display:block}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin:7px 0 0;font-size:.85rem;color:var(--slate)}
.legend .sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.cbreak{list-style:none;padding:0;margin:14px 0 8px}
.cbreak li{display:flex;gap:10px;align-items:baseline;padding:7px 0;border-top:1px solid #ECECEC}
.cbreak li:first-child{border-top:none}
.cbreak .sw{width:11px;height:11px;border-radius:2px;flex:0 0 auto;position:relative;top:1px}
.cbreak .lab{font-weight:600;min-width:150px}
.cbreak .num{font-variant-numeric:tabular-nums;font-weight:700;min-width:30px}
.cbreak .gl{color:var(--slate);font-size:.9rem}
.bs{margin:16px 0 6px;padding:14px 18px;border-radius:8px;border-left:5px solid var(--teal);background:#EAF4F2}
.bs.alert{border-left-color:var(--red);background:#FBEDEF}
.bs h3{margin:0 0 4px;font-size:1.05rem}
.bs>.sub{margin:0 0 10px;color:var(--slate);font-size:.9rem}
.bs .grp{margin:9px 0}
.bs .grp b{display:block;font-size:.95rem}
.bs .grp b.ok{color:var(--teal)}
.bs .grp b.bad{color:var(--red)}
.bs .grp .gl{display:block;color:var(--slate);font-size:.9rem;margin-top:2px}
.bs .files{margin:5px 0 0;padding-left:18px;font-size:.9rem;color:var(--slate)}
.bs .files li{margin:2px 0}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.93rem}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #EDEDED;vertical-align:top}
th{background:#FAFAFA;font-size:.85rem}
th button{all:unset;cursor:pointer;font-weight:700}
.sevm{color:var(--amber);font-weight:600}
.sevc{color:var(--red);font-weight:700}
.tools{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:10px 0}
.tools input[type=search],.tools select{padding:6px 9px;border:1px solid #D6D6D6;border-radius:5px;font:inherit}
.panel{background:#FBF1E4;border-left:4px solid var(--amber);padding:6px 20px 12px}
.panel li{margin:6px 0}
</style></head>
<body><main>
<h1>__TITLE__</h1>
<p class="lede">What one scan found, and which parts of the picture this prototype cannot see.</p>
__BANNER__

<h2>Summary</h2>
<div class="stats" id="sum"></div>

<h2>Coverage</h2>
<p class="cov-head" id="cov-headline"></p>
<div id="cov"></div>
<div id="cov-breakdown"></div>
<p class="muted" id="cov-guard"></p>
<div id="blindspots" class="bs"></div>

<h2>Vulnerability matches linked to components</h2>
<div class="tablewrap"><table><thead><tr><th>Component</th><th>Version</th><th>Matches</th><th>Identifiers</th><th>Severity</th></tr></thead><tbody id="hits"></tbody></table></div>
<p class="muted" id="reconcile"></p>

<h2>All components</h2>
<div class="tools">
  <input type="search" id="q" placeholder="Search name, version, or ID" aria-label="Search components">
  <select id="cat" aria-label="Filter by category"><option value="">All categories</option></select>
  <label><input type="checkbox" id="only"> Only components with matches</label>
  <span class="muted" id="shown"></span>
</div>
<div class="tablewrap"><table><thead><tr>
  <th><button data-k="name">Component</button></th><th><button data-k="version">Version</button></th>
  <th><button data-k="category">Category</button></th><th><button data-k="count">Matches</button></th><th>Why / link status</th>
</tr></thead><tbody id="rows"></tbody></table></div>

<h2>What this cannot tell you</h2>
<div class="panel"><ul>
  <li>Lookup-ready means the prototype recognized the package type and version. The coverage script queries no database itself.</li>
  <li>No linked match is not proof a component is safe. Matches are joined by exact package URL, so a formatting difference could hide one.</li>
  <li>Components missing from the SBOM are invisible here.</li>
  <li>This is one snapshot: one tool version, one vulnerability database date, one copy of the source.</li>
  <li>It is a visibility aid, not a security assessment or a certification.</li>
</ul></div>

__PROV__
</main>
<script>
const D=__DATA__;
const R=D.rows, UNLINKED=D.unlinked;
const $=id=>document.getElementById(id);
const el=(t,txt,cls)=>{const e=document.createElement(t);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e};
const n=c=>R.filter(r=>r.category===c).length;
const linked=R.reduce((s,r)=>s+r.count,0), linkedRows=R.filter(r=>r.count>0).length;

[[R.length,"components listed"],[n("Lookup-ready"),"lookup-ready"],[linked,"vulnerability matches linked"],[linkedRows,"components with matches"]]
  .forEach(([v,l])=>{const s=el("div",undefined,"stat");s.append(el("span",String(v),"big"),el("span",l,"l"));$("sum").append(s)});

const cats=[["Lookup-ready","var(--teal)","Lookup-ready"],["Insufficient data","var(--amber)","Missing details"],["Outside v0 scope","var(--slate)","Not yet supported"],["Excluded","#B8C2C8","Intentionally skipped"]];
function bar(label,counts){
  const wrap=el("div"),tot=counts.reduce((a,b)=>a+b,0)||1;
  wrap.append(el("b",label));
  const b=el("div",undefined,"bar");
  counts.forEach((v,i)=>{const s=el("i");s.style.width=(100*v/tot)+"%";s.style.background=cats[i][1];s.title=cats[i][2]+": "+v;b.append(s)});
  const lg=el("div",undefined,"legend");
  counts.forEach((v,i)=>{const s=el("span");const sw=el("span",undefined,"sw");sw.style.background=cats[i][1];s.append(sw,cats[i][2]+" "+v);lg.append(s)});
  wrap.append(b,lg);return wrap;
}
$("cov").append(bar(D.title,cats.map(x=>n(x[0]))));

$("cov-headline").textContent=n("Lookup-ready")+" of "+R.length+" components could be looked up for known vulnerabilities.";
const gloss={
  "Lookup-ready":"Identified clearly enough to look up known vulnerabilities.",
  "Insufficient data":"Not enough information, like a version number, to look it up.",
  "Outside v0 scope":"A package type this prototype's rules skip. Other scanners may still cover it.",
  "Excluded":"Left out on purpose — dependency lists and other files that aren't third-party packages."
};
const cb=el("ul",undefined,"cbreak");
cats.forEach(cat=>{
  const li=el("li");const sw=el("span",undefined,"sw");sw.style.background=cat[1];
  li.append(sw,el("span",cat[2],"lab"),el("span",String(n(cat[0])),"num"),el("span",gloss[cat[0]]||"","gl"));
  cb.append(li);
});
$("cov-breakdown").append(cb);
$("cov-guard").textContent='"Lookup-ready" means we had enough information to check — not that a component is safe. No known vulnerability is not proof of safety.';

// blind-spot panel -- split "not identifiable by anything" from
// "outside this prototype's rules, but Grype may have checked it anyway"
const unid=R.filter(r=>r.category==="Insufficient data");
const outside=R.filter(r=>r.category==="Outside v0 scope");
const excluded=R.filter(r=>r.category==="Excluded");
const outsideMatches=outside.reduce((s,r)=>s+r.count,0);
const base=s=>String(s).split(/[\\/]/).pop();
const bs=$("blindspots");
const clean=(unid.length===0&&outside.length===0&&UNLINKED===0);
bs.className="bs"+(clean?"":" alert");
bs.append(el("h3",clean?"No blind spots detected in this scan":"Potential blind spots found"));
bs.append(el("p",clean
  ?"Everything in the inventory could be checked, and every finding tied back to a component. Here is what that means — and what was set aside on purpose."
  :"These are places this prototype's coverage rules cannot see. They are not findings — they are gaps in what this tool can judge.","sub"));

const g1=el("div",undefined,"grp");
g1.append(el("b",(unid.length?"":"✓ ")+"Not identifiable: "+unid.length,unid.length?"bad":"ok"));
g1.append(el("span",unid.length
  ?"No scanner can reliably judge these — the SBOM does not say enough about them:"
  :"Every component carried enough identifying information.","gl"));
if(unid.length){const fl=el("ul",undefined,"files");
  unid.forEach(r=>fl.append(el("li",r.name+(r.version?" "+r.version:"")+" — "+(r.reason||""))));g1.append(fl)}
bs.append(g1);

const g2=el("div",undefined,"grp");
g2.append(el("b",(outside.length?"":"✓ ")+"Outside this prototype's lookup rules: "+outside.length,outside.length?"bad":"ok"));
g2.append(el("span",outside.length
  ?"This prototype looks up by package URL within a set list of ecosystems, so it does not classify these. That is a limit of this tool — not a claim that they are safe, and not a claim that nothing checked them:"
  :"Every component fell inside the prototype's ecosystem rules.","gl"));
if(outside.length){const fl=el("ul",undefined,"files");
  outside.forEach(r=>fl.append(el("li",r.name+(r.version?" "+r.version:"")+" — "+(r.reason||"")+(r.count?"  ("+r.count+" matches found anyway)":""))));g2.append(fl)}
if(outsideMatches){const note=el("p",undefined,"gl");note.style.marginTop="7px";
  note.textContent="Grype still found "+outsideMatches+" vulnerability matches in these components. “Outside this prototype's rules” does not mean unchecked, and it does not mean safe.";
  g2.append(note)}
bs.append(g2);

const g3=el("div",undefined,"grp");
g3.append(el("b",(UNLINKED===0?"✓ ":"")+"Findings that did not link: "+UNLINKED,UNLINKED===0?"ok":"bad"));
g3.append(el("span",UNLINKED===0
  ?"Every vulnerability reported tied back to a component by package ID. The combine step counts any that do not."
  :UNLINKED+" finding(s) had no package ID, so they could not be attached to any component.","gl"));
bs.append(g3);

const g4=el("div",undefined,"grp");
g4.append(el("b","Intentionally skipped: "+excluded.length));
g4.append(el("span","Left out on purpose — not third-party packages, so there is nothing to look up. Disclosed, not hidden:","gl"));
if(excluded.length){const fl=el("ul",undefined,"files");
  excluded.forEach(r=>fl.append(el("li",base(r.name)+(r.reason?" — "+r.reason:""))));g4.append(fl)}
bs.append(g4);

const cv=el("p",undefined,"sub");cv.style.marginTop="12px";
cv.textContent="Matches are joined by exact package ID, so a formatting difference could still hide one. No known vulnerability is not proof a component is safe.";
bs.append(cv);

const sevCls=s=>/critical/i.test(s)?"sevc":(/high|medium/i.test(s)?"sevm":undefined);
const hits=R.filter(r=>r.count>0).sort((a,b)=>b.count-a.count);
hits.forEach(r=>{const tr=el("tr");
  tr.append(el("td",r.name),el("td",r.version||"-"),el("td",String(r.count)),
            el("td",(r.ids||"").split("; ").join(", ")),el("td",r.sev,sevCls(r.sev)));
  $("hits").append(tr)});
$("reconcile").textContent=linked+" matches are linked here across "+linkedRows+" components. "
  +(UNLINKED===0?"No finding was dropped by the join.":UNLINKED+" finding(s) could not be linked.")
  +" Counts reflect one scan and are not a claim about the software's overall security.";

const catEl=$("cat");[...new Set(R.map(r=>r.category))].forEach(v=>{const o=el("option",v);o.value=v;catEl.append(o)});
let key="count",dir=-1;
document.querySelectorAll("th button").forEach(b=>b.onclick=()=>{const k=b.dataset.k;dir=(key===k)?-dir:1;key=k;render()});
function render(){
  const q=$("q").value.toLowerCase(),cat=catEl.value,only=$("only").checked;
  const r=R.filter(x=>(!q||(x.name+" "+x.version+" "+x.ids).toLowerCase().includes(q))&&(!cat||x.category===cat)&&(!only||x.count>0));
  r.sort((a,b)=>{const x=a[key],y=b[key];return (typeof x==="number"?x-y:String(x).localeCompare(String(y)))*dir});
  const shown=r.slice(0,300);
  $("rows").replaceChildren(...shown.map(x=>{const tr=el("tr");
    tr.append(el("td",x.name),el("td",x.version||"-"),el("td",x.category),el("td",String(x.count)),
              el("td",x.reason||x.link||"-"));return tr}));
  $("shown").textContent="Showing "+shown.length+" of "+r.length+(r.length>300?" (search to narrow)":"");
}
["q","cat","only"].forEach(id=>{$(id).oninput=render;$(id).onchange=render});
render();
</script></body></html>
"""


def build(outdir, title, note=None, extra_provenance=None):
    """Build the dashboard HTML as a string from an outdir written by
    run_pipeline.py. extra_provenance is an optional list of (label, value)
    pairs to show above the auto-detected Grype facts (e.g. SBOM source,
    download date -- things Grype's own output can't tell us)."""
    outdir = Path(outdir)
    rows = load_rows(outdir / "combined-report.csv")
    grype_json = outdir / "grype.json"
    unlinked = unlinked_count(grype_json) if grype_json.is_file() else 0
    desc = grype_descriptor(grype_json) if grype_json.is_file() else {}

    banner = ""
    if note:
        banner = ('<div class="banner"><b>About this example</b>%s</div>'
                  % htmlmod.escape(note))

    prov_rows = list(extra_provenance or [])
    if desc.get("grype_version"):
        prov_rows.append(("Grype version", desc["grype_version"]))
    if desc.get("db_built"):
        prov_rows.append(("Grype database built", desc["db_built"]))
    if desc.get("scan_timestamp"):
        prov_rows.append(("Scanned", desc["scan_timestamp"]))
    if desc.get("source_type"):
        prov_rows.append(("Scan input", "%s (%s)" % (desc["source_type"], desc.get("source_target", ""))))

    prov = ""
    if prov_rows:
        cells = "".join("<tr><td>%s</td><td>%s</td></tr>"
                        % (htmlmod.escape(str(k)), htmlmod.escape(str(v)))
                        for k, v in prov_rows)
        prov = ('<h2>Provenance</h2><div class="tablewrap"><table><thead><tr>'
                '<th>Item</th><th>Value</th></tr></thead><tbody>%s</tbody></table></div>'
                '<p class="muted">These are what let someone reproduce the numbers. '
                'Pulled directly from the scan output, not typed in by hand.</p>' % cells)

    data = json.dumps({"rows": rows, "unlinked": unlinked, "title": title})
    return (TEMPLATE
            .replace("__TITLE__", htmlmod.escape(title))
            .replace("__BANNER__", banner)
            .replace("__PROV__", prov)
            .replace("__DATA__", data))


def main():
    ap = argparse.ArgumentParser(
        description="Build a standalone dashboard from a pipeline-out folder.")
    ap.add_argument("--outdir", required=True, help="folder written by run_pipeline.py")
    ap.add_argument("--out", required=True, help="HTML file to write")
    ap.add_argument("--title", default="SBOM coverage", help="name of the software analyzed")
    ap.add_argument("--note", help="banner text shown at the top of the page")
    args = ap.parse_args()

    page = build(args.outdir, args.title, note=args.note)
    Path(args.out).write_text(page, encoding="utf-8")

    rows = load_rows(Path(args.outdir) / "combined-report.csv")
    counts = defaultdict(int)
    for r in rows:
        counts[r["category"]] += 1
    linked = sum(r["count"] for r in rows)
    print("Wrote %s" % args.out)
    print("Components: %d  (%s)" % (len(rows), " | ".join(
        "%s %d" % (c, counts.get(c, 0)) for c in ORDER)))
    print("Matches linked: %d" % linked)


if __name__ == "__main__":
    main()
