#!/usr/bin/env python3
"""
LoC dashboard harness for the security-audit campaign.

Walks the four manifest CSVs under <results-root>/findings/_manifest/, finds
every repo whose canonical report already exists on disk, fetches GitHub
`/repos/{o}/{r}/languages` for each unique GitHub-hosted repo, converts
Linguist byte counts to estimated lines-of-code, and renders a self-contained
HTML dashboard.

Outputs (under <results-root>/findings/_manifest/):
  gh-languages-cache.jsonl   one JSON object per repo: {repo, bucket, languages, error?}
  loc-dashboard.html         standalone interactive dashboard

Usage:
  build_loc_dashboard.py [--results-root DIR] [--refresh|--no-fetch]
                         [--workers N] [--open] [--summary]

Requires: `gh` CLI authenticated (uses `gh api`).
"""

import argparse
import csv
import datetime
import json
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
)

MANIFESTS = [
    "audit-manifest.csv",
    "services-manifest.csv",
    "sdl-manifest.csv",
    "supported-releases-manifest.csv",
    "oss-manifest.csv",
]

# ── bytes-per-line conversion ratios (rough empirical averages) ─────────────
BPL = {
    "Go": 27,
    "Python": 33,
    "Java": 42,
    "Kotlin": 38,
    "Scala": 38,
    "Groovy": 35,
    "C": 30,
    "C++": 32,
    "C#": 38,
    "Objective-C": 35,
    "JavaScript": 34,
    "TypeScript": 34,
    "TSX": 36,
    "JSX": 36,
    "Vue": 32,
    "Rust": 35,
    "Ruby": 30,
    "PHP": 35,
    "Perl": 32,
    "Lua": 28,
    "Shell": 30,
    "PowerShell": 35,
    "Batchfile": 25,
    "HTML": 50,
    "CSS": 24,
    "SCSS": 24,
    "Less": 24,
    "YAML": 26,
    "JSON": 28,
    "TOML": 28,
    "XML": 45,
    "INI": 25,
    "Dockerfile": 28,
    "Makefile": 30,
    "CMake": 30,
    "Starlark": 30,
    "HCL": 30,
    "Jinja": 35,
    "Smarty": 35,
    "Mustache": 30,
    "Jsonnet": 30,
    "Jupyter Notebook": 60,
    "Go Template": 35,
    "Markdown": 65,
    "reStructuredText": 55,
    "TeX": 50,
    "AsciiDoc": 55,
    "Protocol Buffer": 30,
    "Thrift": 30,
    "Assembly": 25,
    "PLpgSQL": 35,
    "SQL": 40,
}
BPL_DEFAULT = 35
DOC_LANGS = {
    "Markdown",
    "reStructuredText",
    "TeX",
    "AsciiDoc",
    "HTML",
    "CSS",
    "SCSS",
    "Less",
    "Roff",
    "SVG",
    "Rich Text Format",
}
# Calibration: API estimate ÷ hand-stated "non-vendor non-test" LoC, median
# across spot-checked reports. Used only for the headline "first-party" card.
FIRST_PARTY_DIVISOR = 2.5

LANG_COLORS = {
    "Go": "#00ADD8",
    "Python": "#3572A5",
    "TypeScript": "#3178c6",
    "JavaScript": "#f1e05a",
    "C++": "#f34b7d",
    "C": "#555555",
    "Java": "#b07219",
    "Shell": "#89e051",
    "Rust": "#dea584",
    "Ruby": "#701516",
    "HTML": "#e34c26",
    "CSS": "#563d7c",
    "Go Template": "#00ADD8",
    "Dockerfile": "#384d54",
    "Makefile": "#427819",
    "C#": "#178600",
    "Kotlin": "#A97BFF",
    "PHP": "#4F5D95",
    "HCL": "#844FBA",
    "Starlark": "#76d275",
    "Jsonnet": "#0064bd",
    "PLpgSQL": "#336790",
    "Jinja": "#a52a22",
    "Smarty": "#f0c040",
    "Vue": "#41b883",
    "SCSS": "#c6538c",
    "Perl": "#0298c3",
}


# ─────────────────────────────────────────────────────────────────────────────
def _dashboards_home(config_home):
    try:
        engine = load_engine(config_home)
        dashboards = progress_tracker_dir(engine) / "metrics" / "dashboards"
        dashboards.mkdir(parents=True, exist_ok=True)
        return dashboards
    except SystemExit:
        return None


def _classify_url(url, bucket, seen, github, gitlab_set):
    url = url.strip().rstrip("/")
    if not url or url in seen:
        return
    seen.add(url)
    if "github.com" in url:
        parts = url.split("github.com/", 1)[-1].split("/")
        if len(parts) >= 2:
            slug = f"{parts[0]}/{parts[1].removesuffix('.git')}"
            github.setdefault(slug, bucket)
    elif "gitlab" in url:
        gitlab_set.add(url)


def collect_extra_dir(root, spec, seen, github, gitlab_set):
    """spec is BUCKET=PATH or just PATH (bucket = dir basename).
    Scans PATH/*/*-security-audit.json for metadata.repository."""
    if "=" in spec:
        bucket, path = spec.split("=", 1)
    else:
        path = spec
        bucket = Path(path).name
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = (root / p).resolve()
    n = 0
    for jf in p.glob("*/*-security-audit.json"):
        try:
            with jf.open() as fh:
                meta = json.load(fh).get("metadata", {})
        except Exception:
            continue
        url = meta.get("repository") or meta.get("url") or ""
        if url:
            _classify_url(url, bucket, seen, github, gitlab_set)
            n += 1
    print(f"extra-dir {bucket}/: {n} reports scanned in {p}", file=sys.stderr)


def collect_targets(root, extra_dirs=()):
    """Return ({owner/repo: bucket} for github, gitlab_count)."""
    manifest_dir = root / "findings" / "_manifest"
    seen = set()
    github = {}
    gitlab_set = set()
    for m in MANIFESTS:
        p = manifest_dir / m
        if not p.exists():
            continue
        with p.open() as fh:
            for row in csv.DictReader(fh):
                url = row["url"].strip().rstrip("/")
                if not url or url in seen:
                    continue
                cp = row["canonical_path"].strip()
                rp = root / cp
                if not (
                    rp.exists()
                    or rp.with_suffix(".md").exists()
                    or rp.with_suffix(".json").exists()
                ):
                    continue  # report not yet written
                bucket = "oss-findings" if cp.startswith("oss-findings/") else "findings"
                _classify_url(url, bucket, seen, github, gitlab_set)
    for spec in extra_dirs:
        collect_extra_dir(root, spec, seen, github, gitlab_set)
    return github, len(gitlab_set)


def load_cache(cache_path):
    cache = {}
    if cache_path.exists():
        with cache_path.open() as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    cache[r["repo"]] = r
                except Exception:
                    pass
    return cache


def fetch_one(slug, bucket):
    # CSV-derived slug becomes an API path — constrain to org/repo shape
    # (plan P3)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", slug):
        bucket[slug] = {"error": "unsafe slug"}
        return
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{slug}/languages"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if out.returncode != 0:
            return {
                "repo": slug,
                "bucket": bucket,
                "languages": {},
                "error": out.stderr.strip().split("\n")[0][:120],
            }
        return {"repo": slug, "bucket": bucket, "languages": json.loads(out.stdout)}
    except Exception as e:
        return {"repo": slug, "bucket": bucket, "languages": {}, "error": str(e)[:120]}


def fetch(targets, cache, refresh, workers):
    todo = [(s, b) for s, b in targets.items() if refresh or s not in cache]
    fetched = len(todo)
    if not todo:
        print(f"cache hit: all {len(targets)} repos already cached", file=sys.stderr)
    else:
        print(
            f"fetching {len(todo)} / {len(targets)} repos ({len(targets) - len(todo)} cached) …",
            file=sys.stderr,
        )
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(fetch_one, s, b): s for s, b in todo}
            for fut in as_completed(futs):
                r = fut.result()
                cache[r["repo"]] = r
                done += 1
                if done % 100 == 0 or done == len(todo):
                    print(f"  {done}/{len(todo)}", file=sys.stderr)
    # keep bucket assignment fresh even on cache hit (manifests may move repos)
    for slug, bucket in targets.items():
        if slug in cache:
            cache[slug]["bucket"] = bucket
    # prune cache entries for repos no longer in any manifest
    return {s: cache[s] for s in targets if s in cache}, fetched


def write_cache(cache_path, records):
    with cache_path.open("w") as fh:
        for r in sorted(records.values(), key=lambda x: x["repo"]):
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
def color_for(lang):
    if lang in LANG_COLORS:
        return LANG_COLORS[lang]
    h = sum(ord(c) for c in lang) % 360
    return f"hsl({h},55%,50%)"


def compute(records, gitlab_count):
    repos = []
    lang_totals = defaultdict(lambda: {"loc": 0, "bytes": 0, "repos": 0})
    bucket_stats = defaultdict(
        lambda: {
            "repos": 0,
            "with_data": 0,
            "loc_all": 0,
            "loc_code": 0,
            "bytes": 0,
            "errors": 0,
            "empty": 0,
        }
    )
    for r in records.values():
        bucket = r["bucket"]
        bs = bucket_stats[bucket]
        bs["repos"] += 1
        langs = r.get("languages") or {}
        if not langs:
            if r.get("error"):
                bs["errors"] += 1
            else:
                bs["empty"] += 1
            repos.append(
                {
                    "repo": r["repo"],
                    "bucket": bucket,
                    "loc_all": 0,
                    "loc_code": 0,
                    "bytes": 0,
                    "primary": "—",
                    "langs": {},
                    "status": (r.get("error") or "no-language-data")[:40],
                }
            )
            continue
        bs["with_data"] += 1
        loc_all = loc_code = byts_total = 0
        loc_by_lang = {}
        for lang, byts in langs.items():
            loc = round(byts / BPL.get(lang, BPL_DEFAULT))
            loc_all += loc
            byts_total += byts
            loc_by_lang[lang] = loc
            lt = lang_totals[lang]
            lt["loc"] += loc
            lt["bytes"] += byts
            lt["repos"] += 1
            if lang not in DOC_LANGS:
                loc_code += loc
        primary = max(loc_by_lang.items(), key=lambda x: x[1])[0]
        bs["loc_all"] += loc_all
        bs["loc_code"] += loc_code
        bs["bytes"] += byts_total
        repos.append(
            {
                "repo": r["repo"],
                "bucket": bucket,
                "loc_all": loc_all,
                "loc_code": loc_code,
                "bytes": byts_total,
                "primary": primary,
                "langs": dict(sorted(loc_by_lang.items(), key=lambda x: -x[1])),
                "status": "ok",
            }
        )
    repos.sort(key=lambda x: -x["loc_code"])

    grand = {
        k: sum(b[k] for b in bucket_stats.values())
        for k in ("repos", "with_data", "loc_all", "loc_code", "bytes", "errors", "empty")
    }
    lang_list = sorted(
        [
            {
                "lang": k,
                "loc": v["loc"],
                "bytes": v["bytes"],
                "repos": v["repos"],
                "is_doc": k in DOC_LANGS,
                "color": color_for(k),
            }
            for k, v in lang_totals.items()
        ],
        key=lambda x: -x["loc"],
    )

    return {
        "generated": datetime.date.today().isoformat(),
        "grand": grand,
        "buckets": {k: dict(v) for k, v in bucket_stats.items()},
        "languages": lang_list,
        "repos": repos,
        "gitlab_excluded": gitlab_count,
        "first_party_divisor": FIRST_PARTY_DIVISOR,
    }


def print_summary(data):
    g = data["grand"]
    print()
    print(f"{'Bucket':<16} {'Repos':>8} {'w/data':>8} {'Code LoC':>16} {'Total LoC':>16}")
    print("-" * 70)
    for name, b in data["buckets"].items():
        print(
            f"{name + '/':<16} {b['repos']:>8} {b['with_data']:>8} "
            f"{b['loc_code']:>16,} {b['loc_all']:>16,}"
        )
    print("-" * 70)
    print(
        f"{'TOTAL':<16} {g['repos']:>8} {g['with_data']:>8} "
        f"{g['loc_code']:>16,} {g['loc_all']:>16,}"
    )
    print()
    print(
        f"First-party est. (÷{data['first_party_divisor']}): "
        f"~{round(g['loc_code'] / data['first_party_divisor']):,} LoC"
    )
    print(f"GitLab repos excluded: {data['gitlab_excluded']}")
    print()
    print("Top 10 languages:")
    for lang_item in [x for x in data["languages"] if not x["is_doc"]][:10]:
        pct = 100 * lang_item["loc"] / (g["loc_code"] or 1)
        print(
            f"  {lang_item['lang']:<20} {lang_item['loc']:>14,}  ({pct:5.1f}%)  {lang_item['repos']:>5} repos"
        )


# ─────────────────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit Campaign — LoC Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--red:#f85149}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
h1{margin:0 0 4px;font-size:24px;font-weight:600}
h2{margin:32px 0 12px;font-size:18px;font-weight:600;border-bottom:1px solid var(--border);padding-bottom:8px}
.sub{color:var(--muted);margin-bottom:24px;font-size:13px}
.sub code{background:var(--panel);padding:2px 6px;border-radius:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.card .value{font-size:28px;font-weight:600;font-variant-numeric:tabular-nums}
.card .detail{color:var(--muted);font-size:12px;margin-top:4px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.bucket-row{display:grid;grid-template-columns:140px 1fr 120px 120px;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)}
.bucket-row:last-child{border-bottom:none}
.bucket-row.head{color:var(--muted);font-size:12px;text-transform:uppercase}
.bucket-row .name{font-weight:600}
.bucket-row .num{text-align:right;font-variant-numeric:tabular-nums}
.bar-track{height:24px;background:#0d1117;border-radius:4px;overflow:hidden;position:relative}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),#1f6feb);display:flex;align-items:center;padding:0 8px;font-size:12px;font-weight:600}
.lang-row{display:grid;grid-template-columns:160px 1fr 110px 70px 60px;gap:12px;align-items:center;padding:6px 0;font-size:13px}
.lang-row .swatch{width:12px;height:12px;border-radius:3px;display:inline-block;margin-right:8px;vertical-align:middle}
.lang-row .num{text-align:right;font-variant-numeric:tabular-nums}
.lang-bar{height:16px;background:#0d1117;border-radius:3px;overflow:hidden}
.lang-fill{height:100%}
.doc-lang{opacity:.5}
.controls{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.controls input,.controls select{background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;font-family:inherit}
.controls input[type=text]{width:280px}
.controls .count{color:var(--muted);font-size:13px;margin-left:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;position:sticky;top:0;background:var(--panel)}
thead th:hover{color:var(--text)}
thead th .arrow{opacity:.4;margin-left:4px}
thead th.sorted .arrow{opacity:1;color:var(--accent)}
tbody td{padding:8px 10px;border-bottom:1px solid #21262d}
tbody tr:hover{background:#1c2128}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.repo-link{color:var(--accent);text-decoration:none}
.repo-link:hover{text-decoration:underline}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600}
.pill{background:#6e768133;color:#8b949e}
.pill.findings{background:#1f6feb33;color:#79c0ff}
.pill.oss-findings{background:#3fb95033;color:#56d364}
.pill.OpenStack-k8s-ops{background:#db61a233;color:#ff7eb6}
.pill.ecoengg-findings{background:#e3b34133;color:#e3b341}
.lang-stack{display:flex;height:8px;border-radius:3px;overflow:hidden;min-width:120px}
.lang-stack span{display:block;height:100%}
.table-wrap{max-height:600px;overflow-y:auto;border:1px solid var(--border);border-radius:6px}
.status-err{color:var(--red);font-size:11px}
.status-empty{color:var(--muted);font-size:11px}
.footer{color:var(--muted);font-size:12px;margin-top:32px;border-top:1px solid var(--border);padding-top:16px}
.toggle{cursor:pointer;color:var(--accent);font-size:12px}
</style></head><body>

<h1>Security Audit Campaign — Lines of Code Dashboard</h1>
<div class="sub">
  Estimated via GitHub <code>/repos/{owner}/{repo}/languages</code> (Linguist bytes ÷ avg bytes-per-line).
  Linguist excludes <code>vendor/</code>, <code>node_modules/</code>, generated code.
  Generated <span id="gen-date"></span>.
</div>

<div class="cards">
  <div class="card"><div class="label">Code LoC (est.)</div><div class="value" id="g-loc-code"></div><div class="detail">excl. docs/markup</div></div>
  <div class="card"><div class="label">Total LoC (est.)</div><div class="value" id="g-loc-all"></div><div class="detail">incl. HTML/CSS/MD</div></div>
  <div class="card"><div class="label">First-party (÷<span id="fpd"></span>×)</div><div class="value" id="g-loc-fp"></div><div class="detail">non-test calibrated est.</div></div>
  <div class="card"><div class="label">Repos audited</div><div class="value" id="g-repos"></div><div class="detail"><span id="g-with-data"></span> w/ data · <span id="g-err"></span> err · <span id="g-empty"></span> empty</div></div>
  <div class="card"><div class="label">Source bytes</div><div class="value" id="g-bytes"></div><div class="detail">non-vendored</div></div>
  <div class="card"><div class="label">Not estimated</div><div class="value" id="g-gitlab"></div><div class="detail">GitLab-hosted repos</div></div>
</div>

<h2>By bucket</h2><div class="panel" id="bucket-panel"></div>
<h2>By language <span class="toggle" id="lang-toggle">(show all)</span></h2><div class="panel" id="lang-panel"></div>

<h2>Repositories</h2>
<div class="panel">
  <div class="controls">
    <input type="text" id="filter" placeholder="Filter repo / language…">
    <select id="bucket-filter"><option value="">All buckets</option></select>
    <select id="status-filter"><option value="">All statuses</option><option value="ok">With data</option><option value="err">Errors / empty</option></select>
    <label style="font-size:13px;color:var(--muted)">Min LoC <input type="number" id="min-loc" value="0" style="width:90px"></label>
    <span class="count" id="row-count"></span>
  </div>
  <div class="table-wrap"><table id="repo-table">
    <thead><tr>
      <th data-sort="repo">Repository<span class="arrow">↕</span></th>
      <th data-sort="bucket">Bucket<span class="arrow">↕</span></th>
      <th data-sort="primary">Primary lang<span class="arrow">↕</span></th>
      <th data-sort="loc_code" class="num">Code LoC<span class="arrow">↕</span></th>
      <th data-sort="loc_all" class="num">Total LoC<span class="arrow">↕</span></th>
      <th data-sort="bytes" class="num">Bytes<span class="arrow">↕</span></th>
      <th>Mix</th>
    </tr></thead><tbody id="repo-tbody"></tbody>
  </table></div>
</div>

<div class="footer">
  Source: <code>findings/_manifest/gh-languages-cache.jsonl</code> ·
  Conversion ratios are language-specific approximations; calibration vs hand-stated report LoC shows API estimates run ~<span id="fpd2"></span>× higher (tests + fixtures + tooling included). ·
  <span id="g-gitlab2"></span> internal GitLab repos excluded.
</div>

__POPULATION__

<script id="dashboard-data" type="application/json">__DATA__</script>
<script>
const DATA=JSON.parse(document.getElementById('dashboard-data').textContent);
const fmt=n=>n.toLocaleString('en-US');
const fmtBytes=n=>n>=1e9?(n/1e9).toFixed(2)+' GB':n>=1e6?(n/1e6).toFixed(1)+' MB':n>=1e3?(n/1e3).toFixed(0)+' KB':n+' B';
const colorFor=lang=>{const l=DATA.languages.find(x=>x.lang===lang);return l?l.color:'#6e7681'};

document.getElementById('gen-date').textContent=DATA.generated;
document.getElementById('g-loc-code').textContent=fmt(DATA.grand.loc_code);
document.getElementById('g-loc-all').textContent=fmt(DATA.grand.loc_all);
document.getElementById('fpd').textContent=DATA.first_party_divisor;
document.getElementById('fpd2').textContent=DATA.first_party_divisor;
document.getElementById('g-loc-fp').textContent='~'+fmt(Math.round(DATA.grand.loc_code/DATA.first_party_divisor));
document.getElementById('g-repos').textContent=fmt(DATA.grand.repos);
document.getElementById('g-with-data').textContent=fmt(DATA.grand.with_data);
document.getElementById('g-err').textContent=fmt(DATA.grand.errors);
document.getElementById('g-empty').textContent=fmt(DATA.grand.empty);
document.getElementById('g-bytes').textContent=fmtBytes(DATA.grand.bytes);
document.getElementById('g-gitlab').textContent=fmt(DATA.gitlab_excluded);
document.getElementById('g-gitlab2').textContent=fmt(DATA.gitlab_excluded);
{const sel=document.getElementById('bucket-filter');
 for(const n of Object.keys(DATA.buckets)){const o=document.createElement('option');o.value=n;o.textContent=n+'/';sel.appendChild(o)}}

(()=>{const p=document.getElementById('bucket-panel');
const max=Math.max(...Object.values(DATA.buckets).map(b=>b.loc_code),1);
let h=`<div class="bucket-row head"><div>Bucket</div><div>Code LoC</div><div class="num">Repos</div><div class="num">Bytes</div></div>`;
for(const[n,b]of Object.entries(DATA.buckets)){
  h+=`<div class="bucket-row"><div class="name">${n}/</div>
  <div class="bar-track"><div class="bar-fill" style="width:${(b.loc_code/max*100).toFixed(1)}%">${fmt(b.loc_code)}</div></div>
  <div class="num">${fmt(b.with_data)} / ${fmt(b.repos)}</div><div class="num">${fmtBytes(b.bytes)}</div></div>`}
p.innerHTML=h})();

let langShowAll=false;
function renderLangs(){const p=document.getElementById('lang-panel');
const ls=langShowAll?DATA.languages:DATA.languages.slice(0,20);
const max=DATA.languages[0]?.loc||1,tot=DATA.grand.loc_code||1;let h='';
for(const l of ls){h+=`<div class="lang-row ${l.is_doc?'doc-lang':''}">
<div><span class="swatch" style="background:${l.color}"></span>${l.lang}${l.is_doc?' <span style="font-size:10px;color:var(--muted)">(doc)</span>':''}</div>
<div class="lang-bar"><div class="lang-fill" style="width:${(l.loc/max*100).toFixed(2)}%;background:${l.color}"></div></div>
<div class="num">${fmt(l.loc)}</div><div class="num">${(l.loc/tot*100).toFixed(1)}%</div>
<div class="num" style="color:var(--muted)">${l.repos}</div></div>`}
p.innerHTML=h;
document.getElementById('lang-toggle').textContent=langShowAll?'(show top 20)':`(show all ${DATA.languages.length})`}
document.getElementById('lang-toggle').onclick=()=>{langShowAll=!langShowAll;renderLangs()};
renderLangs();

let sortKey='loc_code',sortDir=-1;
function renderTable(){
const q=document.getElementById('filter').value.toLowerCase().trim();
const bf=document.getElementById('bucket-filter').value;
const sf=document.getElementById('status-filter').value;
const ml=parseInt(document.getElementById('min-loc').value)||0;
let rows=DATA.repos.filter(r=>{
  if(bf&&r.bucket!==bf)return false;
  if(sf==='ok'&&r.status!=='ok')return false;
  if(sf==='err'&&r.status==='ok')return false;
  if(r.loc_code<ml)return false;
  if(q&&!(r.repo.toLowerCase().includes(q)||r.primary.toLowerCase().includes(q)))return false;
  return true});
rows.sort((a,b)=>{const av=a[sortKey],bv=b[sortKey];
  return typeof av==='number'?(av-bv)*sortDir:String(av).localeCompare(String(bv))*sortDir});
const sum=rows.reduce((s,r)=>s+r.loc_code,0);
document.getElementById('row-count').textContent=`${fmt(rows.length)} repos · ${fmt(sum)} code LoC`;
const disp=rows.slice(0,1000);
document.getElementById('repo-tbody').innerHTML=disp.map(r=>{
  let mix='';
  if(r.status==='ok'){const t=r.loc_all||1;const top=Object.entries(r.langs).slice(0,6);
    mix='<div class="lang-stack" title="'+top.map(([l,n])=>`${l}: ${fmt(n)}`).join(' · ')+'">'+
    top.map(([l,n])=>`<span style="width:${(n/t*100).toFixed(1)}%;background:${colorFor(l)}"></span>`).join('')+'</div>'}
  else mix=`<span class="${r.status.includes('no-language')?'status-empty':'status-err'}">${r.status}</span>`;
  return`<tr><td><a class="repo-link" href="https://github.com/${r.repo}" target="_blank">${r.repo}</a></td>
  <td><span class="pill ${r.bucket}">${r.bucket}</span></td>
  <td><span class="swatch" style="background:${colorFor(r.primary)};width:10px;height:10px;display:inline-block;border-radius:2px;margin-right:6px"></span>${r.primary}</td>
  <td class="num">${fmt(r.loc_code)}</td><td class="num">${fmt(r.loc_all)}</td>
  <td class="num">${fmtBytes(r.bytes)}</td><td>${mix}</td></tr>`}).join('')+
  (rows.length>1000?`<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:12px">… ${fmt(rows.length-1000)} more (refine filter)</td></tr>`:'');
document.querySelectorAll('thead th').forEach(th=>{
  th.classList.toggle('sorted',th.dataset.sort===sortKey);
  const a=th.querySelector('.arrow');if(!a)return;
  a.textContent=th.dataset.sort===sortKey?(sortDir>0?'↑':'↓'):'↕'})}
document.querySelectorAll('thead th[data-sort]').forEach(th=>{
  th.onclick=()=>{const k=th.dataset.sort;
    if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=(k==='repo'||k==='bucket'||k==='primary')?1:-1}
    renderTable()}});
['filter','bucket-filter','status-filter','min-loc'].forEach(id=>
  document.getElementById(id).addEventListener('input',renderTable));
renderTable();
</script></body></html>
"""


def render(dashboard_path, data, pop_html=""):
    out = HTML.replace("__DATA__", json.dumps(data, separators=(",", ":")))
    out = out.replace("__POPULATION__", pop_html)
    dashboard_path.write_text(out, encoding="utf-8")
    return len(out)


# --- standard population block (traust.cli.groups.corpus; best-effort) ------------


def _population_lines(extra_dirs, counts):
    """Markdown lines of the standard population block, [] if corpus.py is
    unavailable — the dashboard must render either way."""
    try:
        import importlib

        corpus = importlib.import_module("traust_engine.corpus.resolver")
        cfg = corpus.load_config()
        extra = [
            "manifest CSVs under analysis-results/findings/_manifest/ "
            "(audit, services, sdl, supported-releases, oss)"
        ]
        extra += [f"`--extra-dir {s}`" for s in extra_dirs]
        roots = corpus.roots_description(cfg, None, extra=extra)
        return corpus.population_block_lines(
            tool="loc-dashboard",
            roots=roots,
            unit="estimated lines of code (GitHub Linguist bytes ÷ bytes-per-line)",
            filters="manifest rows kept only when canonical_path report "
            "exists on disk; GitLab-hosted repos counted "
            "separately/excluded from GH Linguist totals",
            denominator="manifest CSV rows ∩ reports on disk (NOT a directory walk)",
            counts=counts,
        )
    except Exception as e:
        print(f"population block omitted: {e}", file=sys.stderr)
        return []


def _population_html(lines):
    """Render the population block lines as a final HTML panel."""
    if not lines:
        return ""
    import html as _html
    import re as _re

    lis = []
    for ln in lines:
        if not ln.startswith("- "):
            continue  # heading/blank handled by the <h2> below
        t = _html.escape(ln[2:], quote=True)
        t = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        lis.append(f"<li>{t}</li>")
    return (
        '<h2>Population</h2><div class="panel"><ul style="margin:0;'
        "padding-left:18px;color:var(--muted);font-size:13px;"
        'line-height:1.9">' + "".join(lis) + "</ul></div>"
    )


# ─────────────────────────────────────────────────────────────────────────────


# --- shared metrics ledger (best-effort; dashboards never fail on it) -------


def _ledger_soft(results_root):
    try:
        import importlib
        from pathlib import Path as _P

        mod = importlib.import_module("traust_engine.metrics.history")
        ws = _P(results_root).resolve().parent
        if (ws / "progress-tracker").is_dir():
            return mod, ws
    except Exception:
        pass
    return None, None


def _inject_trend(path, text):
    """Insert the trend line into an already-rendered output (md or html)."""
    try:
        import re as _re
        from pathlib import Path as _P

        p = _P(path)
        s = p.read_text(encoding="utf-8")
        if p.suffix == ".md":
            head, _, rest = s.partition("\n")
            s = head + f"\n\n\U0001f4c8 *{text}*\n" + rest
        else:
            s = _re.sub(
                r"(<body[^>]*>)",
                lambda m: (
                    m.group(1) + "<div style='max-width:1280px;margin:10px auto 0;"
                    "padding:0 28px;font-size:13px;color:#6a6e73'>"
                    "\U0001f4c8 " + text + "</div>"
                ),
                s,
                count=1,
            )
        p.write_text(s, encoding="utf-8")
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (contains findings/_manifest/). "
        "Default: $AUDIT_RESULTS_ROOT or locations.yaml.",
    )
    ap.add_argument(
        "--extra-dir",
        metavar="[BUCKET=]PATH",
        action="append",
        default=[],
        help="extra report directory (no manifest CSV): scans "
        "PATH/*/*-security-audit.json and reads metadata.repository. "
        "Bucket label defaults to the directory basename. Repeatable.",
    )
    ap.add_argument("--refresh", action="store_true", help="ignore cache, refetch every repo")
    ap.add_argument(
        "--no-fetch",
        action="store_true",
        help="skip API; rebuild dashboard from existing cache only",
    )
    ap.add_argument("--workers", type=int, default=20, help="concurrent gh api calls (default 20)")
    ap.add_argument("--open", action="store_true", help="open dashboard in browser when done")
    ap.add_argument(
        "--summary", action="store_true", help="print plain-text summary tables to stdout"
    )
    args = ap.parse_args()

    root = resolve_results_root(args)
    manifest_dir = root / "findings" / "_manifest"
    cache_path = manifest_dir / "gh-languages-cache.jsonl"
    dashboard_path = (_dashboards_home(args.config_home) or manifest_dir) / "loc-dashboard.html"
    print(f"results root: {root}", file=sys.stderr)

    targets, gitlab = collect_targets(root, args.extra_dir)
    print(
        f"manifests: {len(targets)} unique GitHub repos with completed "
        f"reports ({gitlab} GitLab repos excluded)",
        file=sys.stderr,
    )

    cache = load_cache(cache_path)
    if args.no_fetch:
        records = {s: cache[s] for s in targets if s in cache}
        for s, b in targets.items():
            if s in records:
                records[s]["bucket"] = b
        fetched = 0
        missing = len(targets) - len(records)
        if missing:
            print(
                f"warning: --no-fetch but {missing} repos not in cache; they will be omitted",
                file=sys.stderr,
            )
    else:
        records, fetched = fetch(targets, cache, args.refresh, args.workers)
        write_cache(cache_path, records)
        print(f"wrote {cache_path.relative_to(root)} ({len(records)} repos)", file=sys.stderr)

    data = compute(records, gitlab)
    g = data["grand"]
    pop_lines = _population_lines(
        args.extra_dir,
        {
            "Manifest repos in scope (rows ∩ reports on disk, deduped)": f"{len(targets):,} GitHub ({gitlab:,} GitLab counted separately)",
            "Repos with LoC data": f"{g['with_data']:,}",
            "Repos skipped": f"{g['errors']:,} fetch errors · {g['empty']:,} no language "
            f"data · {gitlab:,} GitLab (not sized)",
        },
    )
    size = render(dashboard_path, data, _population_html(pop_lines))

    ml, _ws = _ledger_soft(root)
    if ml:
        headline = {
            "total_loc": g.get("loc_code"),
            "repos_with_loc": g.get("repos"),
            "languages": len(data.get("languages") or []),
        }
        prev = ml.previous("loc-dashboard")
        tline = ml.trend_line(headline, prev, ["total_loc", "repos_with_loc", "languages"])
        if tline:
            _inject_trend(dashboard_path, tline)
        if ml.append_if_changed("loc-dashboard", headline):
            print("metrics snapshot appended (loc-dashboard)", file=sys.stderr)
    print(
        f"wrote {dashboard_path} "
        f"({size:,} bytes, {g['repos']} repos, {g['loc_code']:,} code LoC, "
        f"{fetched} fetched / {len(records) - fetched} cached)",
        file=sys.stderr,
    )

    if args.summary:
        print_summary(data)

    if args.open:
        subprocess.run(
            ["open" if sys.platform == "darwin" else "xdg-open", str(dashboard_path)], check=False
        )


if __name__ == "__main__":
    main()
