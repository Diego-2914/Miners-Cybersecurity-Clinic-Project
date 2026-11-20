#!/usr/bin/env python3
"""make_dashboard.py -- turn a combined-report.csv into a standalone dashboard.

  python make_dashboard.py --report pipeline-out/combined-report.csv \
      --title "Clinical integration server" --out dashboard.html

  Options:
    --grype pipeline-out/grype.json   count findings that did not link (honest
                                      blind-spot number instead of assuming 0)
    --note  "text"                    a banner at the top (use this to say
                                      plainly when an SBOM is illustrative)
    --prov  "Label=Value"             repeatable provenance rows

The page has no build step and no dependencies: open the HTML file directly.
"""
import argparse
import csv
import html
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


def load_rows(report_csv):
    with open(report_csv, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        try:
            count = int(r.get("grype_match_count") or 0)
        except ValueError:
            count = 0
        out.append({
            "name": r.get("name", ""),
            "version": r.get("version", ""),
            "purl": r.get("purl", ""),
            "type": r.get("type", ""),
            "category": r.get("category", ""),
            "reason": r.get("reason", ""),
            "count": count,
            "ids": r.get("grype_vulnerability_ids", ""),
            "sev": r.get("grype_severities", ""),
            "link": r.get("grype_link_status", ""),
        })
    return out


def unlinked_count(grype_json):
    """Grype matches that carry no purl -- the join cannot attach these to
    any component, so they are a real blind spot, not a clean result."""
    data = read_json(grype_json)
    n = 0
    for m in data.get("matches", []):
        if not (m.get("artifact") or {}).get("purl", ""):
            n += 1
    return n


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
  "Outside v0 scope":"A package type this early version doesn't handle.",
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

// blind-spot panel
const gaps=n("Insufficient data")+n("Outside v0 scope");
const excluded=R.filter(r=>r.category==="Excluded");
const bs=$("blindspots");const clean=(gaps===0&&UNLINKED===0);
bs.className="bs"+(clean?"":" alert");
bs.append(el("h3",clean?"No blind spots detected in this scan":"Potential blind spots found"));
bs.append(el("p",clean
  ?"Everything in the inventory could be checked, and every finding tied back to a component. Here is what that means — and what was set aside on purpose."
  :"Some parts of this software could not be checked. These are the gaps to be aware of — they are not findings, they are places this scan cannot see.","sub"));

const g1=el("div",undefined,"grp");
g1.append(el("b",(clean?"✓ ":"")+"Could not be checked: "+gaps,gaps===0?"ok":"bad"));
g1.append(el("span",gaps===0?"Every component had enough data and a supported package type.":"These components are in the inventory but this version could not look them up:","gl"));
if(gaps){
  const fl=el("ul",undefined,"files");
  R.filter(r=>r.category==="Insufficient data"||r.category==="Outside v0 scope")
   .forEach(r=>fl.append(el("li",r.name+(r.version?" "+r.version:"")+" — "+(r.reason||r.category))));
  g1.append(fl);
}
bs.append(g1);

const g2=el("div",undefined,"grp");
g2.append(el("b",(UNLINKED===0?"✓ ":"")+"Findings that did not link: "+UNLINKED,UNLINKED===0?"ok":"bad"));
g2.append(el("span",UNLINKED===0
  ?"Every vulnerability reported tied back to a component by package ID. The combine step counts any that do not."
  :UNLINKED+" finding(s) had no package ID, so they could not be attached to any component.","gl"));
bs.append(g2);

const g3=el("div",undefined,"grp");
g3.append(el("b","Intentionally skipped: "+excluded.length));
g3.append(el("span","Left out on purpose — not third-party packages, so there is nothing to look up. Disclosed, not hidden:","gl"));
if(excluded.length){
  const fl=el("ul",undefined,"files");
  excluded.forEach(r=>fl.append(el("li",String(r.name).split(/[\\/]/).pop()+(r.reason?" — "+r.reason:""))));
  g3.append(fl);
}
bs.append(g3);

const cv=el("p",undefined,"sub");cv.style.marginTop="12px";
cv.textContent="Matches are joined by exact package ID, so a formatting difference could still hide one. No known vulnerability is not proof a component is safe.";
bs.append(cv);

// matches
const sevCls=s=>/critical/i.test(s)?"sevc":(/high|medium/i.test(s)?"sevm":undefined);
const hits=R.filter(r=>r.count>0).sort((a,b)=>b.count-a.count);
hits.forEach(r=>{const tr=el("tr");
  tr.append(el("td",r.name),el("td",r.version||"-"),el("td",String(r.count)),
            el("td",r.ids.split("; ").join(", ")),el("td",r.sev,sevCls(r.sev)));
  $("hits").append(tr)});
$("reconcile").textContent=linked+" matches are linked here across "+linkedRows+" components. "
  +(UNLINKED===0?"No finding was dropped by the join.":UNLINKED+" finding(s) could not be linked.")
  +" Counts reflect one scan and are not a claim about the software's overall security.";

// all components
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


def main():
    ap = argparse.ArgumentParser(
        description="Build a standalone dashboard from a combined-report.csv")
    ap.add_argument("--report", required=True, help="combined-report.csv from the pipeline")
    ap.add_argument("--out", required=True, help="HTML file to write")
    ap.add_argument("--title", default="SBOM coverage", help="name of the software analyzed")
    ap.add_argument("--grype", help="grype.json, to count findings that did not link")
    ap.add_argument("--note", help="banner text shown at the top of the page")
    ap.add_argument("--prov", action="append", default=[],
                    help='provenance row as "Label=Value" (repeatable)')
    args = ap.parse_args()

    rows = load_rows(args.report)
    unlinked = unlinked_count(args.grype) if args.grype else 0

    banner = ""
    if args.note:
        banner = ('<div class="banner"><b>About this example</b>%s</div>'
                  % html.escape(args.note))

    prov = ""
    if args.prov:
        cells = []
        for item in args.prov:
            label, _, value = item.partition("=")
            cells.append("<tr><td>%s</td><td>%s</td></tr>"
                         % (html.escape(label.strip()), html.escape(value.strip())))
        prov = ('<h2>Provenance</h2><div class="tablewrap"><table><thead><tr>'
                '<th>Item</th><th>Value</th></tr></thead><tbody>%s</tbody></table></div>'
                '<p class="muted">These are what let someone reproduce the numbers.</p>'
                % "".join(cells))

    data = json.dumps({"rows": rows, "unlinked": unlinked, "title": args.title})
    page = (TEMPLATE
            .replace("__TITLE__", html.escape(args.title))
            .replace("__BANNER__", banner)
            .replace("__PROV__", prov)
            .replace("__DATA__", data))

    Path(args.out).write_text(page, encoding="utf-8")

    counts = defaultdict(int)
    for r in rows:
        counts[r["category"]] += 1
    linked = sum(r["count"] for r in rows)
    print("Wrote %s" % args.out)
    print("Components: %d  (%s)" % (len(rows), " | ".join(
        "%s %d" % (c, counts.get(c, 0)) for c in ORDER)))
    print("Matches linked: %d | findings that did not link: %d" % (linked, unlinked))


if __name__ == "__main__":
    main()
