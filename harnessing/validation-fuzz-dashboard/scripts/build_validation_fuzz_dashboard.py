#!/usr/bin/env python3
"""build_validation_fuzz_dashboard.py — combined live-validation + fuzzing dashboard.

Walks every validations/*/*validation*.json (live-validation verdicts against
audit findings) and parses FUZZ-CAMPAIGN-SUMMARY.md (offline fuzz campaign),
then emits a single self-contained HTML dashboard (inline SVG, no CDN):

  Live-validation-fuzz-dashboard.html

Idempotent — re-running overwrites the output. No network access.
"""

import argparse
import collections
import datetime
import html
import json
import re
import sys
from pathlib import Path

from traust.context import (
    add_config_home_arg,
    campaign_settings,
    load_engine,
    progress_tracker_dir,
    resolve_results_root,
    workspace_dir,
)

VERDICTS = ["CONFIRMED", "INCONCLUSIVE", "BLOCKED_BY_SCOPE", "REFUTED"]  # attempted, bad->good
SEVS = ["critical", "high", "medium", "low", "informational"]

# status palette (dataviz reference instance) — verdicts are states, not series
VCOLOR = {
    "CONFIRMED": "#d03b3b",  # critical
    "INCONCLUSIVE": "#fab219",  # warning
    "BLOCKED_BY_SCOPE": "#ec835a",  # serious
    "REFUTED": "#0ca30c",  # good
}
VLABEL = {
    "CONFIRMED": "Confirmed exploitable",
    "INCONCLUSIVE": "Inconclusive",
    "BLOCKED_BY_SCOPE": "Blocked by scope",
    "REFUTED": "Refuted",
}


def _tracking_suffix(sep: str) -> str:
    """The deployment's tracking reference (campaign.yaml), or nothing."""
    ref = campaign_settings().get("tracking_reference")
    return f"{sep}{ref}" if ref else ""


def esc(s):
    return html.escape(str(s), quote=True)


def target_name(report):
    t = (report.get("title") or "").replace("Live Validation Report", "")
    return t.strip(" —-–") or "unknown"


def scan_validations(root):
    stats = {
        "reports": 0,
        "verdict_sev": collections.defaultdict(collections.Counter),  # verdict -> sev counter
        "not_attempted": 0,
        "na_sev": collections.Counter(),
        "per_target": collections.Counter(),  # target -> confirmed count
        "per_target_crit": collections.Counter(),  # target -> confirmed criticals
        "confirmed_crit": [],  # (target, title, impact)
        "chains_total": 0,
        "chains_live": 0,  # >=1 confirmed step
        "needs_credential": 0,
    }
    seen_crit = set()
    pat = Path(root) / "validations"
    for sub in sorted(pat.iterdir()):
        if not sub.is_dir():
            continue
        for fn in sub.iterdir():
            if "validation" not in fn.name or not fn.name.endswith(".json"):
                continue
            try:
                rep = json.load(fn.open())
            except Exception:
                continue
            stats["reports"] += 1
            tgt = target_name(rep)
            stats["needs_credential"] += len(rep.get("needs_credential") or [])
            for ch in rep.get("attack_chains") or []:
                stats["chains_total"] += 1
                steps = ch.get("steps") or []
                if any((s.get("verdict") or "").lower() == "confirmed" for s in steps):
                    stats["chains_live"] += 1
            for it in rep.get("validated_findings") or []:
                v = (it.get("verdict") or "?").upper()
                s = (it.get("claimed_severity") or "?").lower()
                if v == "NOT_ATTEMPTED":
                    stats["not_attempted"] += 1
                    stats["na_sev"][s] += 1
                    continue
                if v not in VERDICTS:
                    continue
                stats["verdict_sev"][v][s] += 1
                if v == "CONFIRMED":
                    stats["per_target"][tgt] += 1
                    if s == "critical":
                        stats["per_target_crit"][tgt] += 1
                        key = (tgt, (it.get("title") or "")[:120])
                        if key not in seen_crit:
                            seen_crit.add(key)
                            stats["confirmed_crit"].append(
                                (tgt, it.get("title") or "?", it.get("observed_impact") or "")
                            )
    return stats


def parse_md_tables(path):
    """Return list of tables; each table is a list of row-lists (header first)."""
    tables, cur = [], []
    for line in open(path, encoding="utf-8"):
        if line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                continue
            cur.append(cells)
        elif cur:
            tables.append(cur)
            cur = []
    if cur:
        tables.append(cur)
    return tables


def scan_fuzz(root):
    out = {"batches": [], "bugs": [], "patterns": [], "totals": {}}
    # Preferred source: the machine-readable sidecar emitted by
    # harnessing/6-fuzz/create-fuzzing/scripts/build_fuzz_rollup.py. The markdown scrape
    # below is the fallback for trees generated before the sidecar existed.
    jpath = root / "FUZZ-CAMPAIGN-SUMMARY.json"
    if jpath.exists():
        try:
            side = json.loads(jpath.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            side = None
        if side and side.get("totals"):
            t = side["totals"]
            out["totals"] = {
                "targets": f"{t.get('targets', '—')}",
                "fuzzers": f"{t.get('fuzz_functions', '—')}",
                "bugs": f"{t.get('bugs', '—')}",
                "advisories": f"{t.get('advisories', '—')}",
            }
            out["bugs"] = [
                [
                    str(b.get("num", "")),
                    b.get("target", ""),
                    b.get("title", ""),
                    str(b.get("cvss", "")),
                    str(b.get("cwe", "")),
                    b.get("advisory") or "—",
                    b.get("method", ""),
                ]
                for b in side.get("bugs", [])
            ]
            out["patterns"] = [
                {
                    "name": p.get("name", ""),
                    "tested": p.get("tested", 0),
                    "vuln": p.get("vulnerable", 0),
                    "advisory": p.get("advisory") or "—",
                }
                for p in side.get("patterns", [])
            ]
            out["batches"] = side.get("batches", [])
            return out
    path = root / "FUZZ-CAMPAIGN-SUMMARY.md"
    if not path.exists():
        return out
    with path.open(encoding="utf-8") as fh:
        m = re.search(r"([\d,]+) portfolio advisories", fh.read())
    if m:
        out["totals"]["advisories"] = m.group(1)
    for tbl in parse_md_tables(path):
        hdr = [h.lower() for h in tbl[0]]
        if "strategy" in hdr or ("batch" in hdr and "targets" in hdr):
            # Two summary layouts: legacy Batch|Strategy|Targets|Fuzzers|
            # Bugs (values at 2/3/4) and current Batch|Targets|Fuzz
            # functions|Real bugs|Bug #s (values at 1/2/3).
            off = 2 if "strategy" in hdr else 1
            for row in tbl[1:]:
                if row[0].strip("* ").lower() == "total":
                    out["totals"].update(
                        targets=row[off].strip("* "),
                        fuzzers=row[off + 1].strip("* "),
                        bugs=row[off + 2].strip("* ").lstrip("≥>= "),
                    )
                else:
                    out["batches"].append(row)
        elif "cvss" in hdr and "bug" in hdr:
            out["bugs"] = tbl[1:]
        elif "pattern" in hdr and "rate" in hdr:
            for row in tbl[1:]:
                m_t = re.search(r"\d+", row[1] or "0")
                m_v = re.search(r"\d+", row[2] or "0")
                out["patterns"].append(
                    {
                        "name": row[0].strip("`"),
                        "tested": int(m_t.group()) if m_t else 0,
                        "vuln": int(m_v.group()) if m_v else 0,
                        "advisory": row[4] if len(row) > 4 else "",
                    }
                )
    return out


# ---------------------------------------------------------------- SVG helpers
BAR_H = 20  # <=24px mark
GAP = 2  # surface gap
ROW_H = 34


def stacked_bar_rows(vs, width=640, label_w=150, val_w=110):
    """Verdict share per severity, % of attempted. Returns svg + table rows."""
    plot_w = width - label_w - val_w
    rows_svg, rows_tbl = [], []
    y = 0
    for sev in SEVS:
        counts = [vs[v].get(sev, 0) for v in VERDICTS]
        total = sum(counts)
        rows_tbl.append((sev.capitalize(), counts, total))
        if total == 0:
            continue
        x = label_w
        segs = []
        for v, n in zip(VERDICTS, counts, strict=False):
            if n == 0:
                continue
            w = plot_w * n / total
            segs.append((v, n, x, w))
            x += w
        parts = [
            f'<text x="{label_w - 10}" y="{y + BAR_H / 2}" text-anchor="end" '
            f'dominant-baseline="central" class="axis">{esc(sev.capitalize())}</text>'
        ]
        for i, (v, n, sx, w) in enumerate(segs):
            wpx = max(w - (GAP if i < len(segs) - 1 else 0), 1)
            pct = 100.0 * n / total
            parts.append(
                f'<rect class="seg" x="{sx:.1f}" y="{y}" width="{wpx:.1f}" height="{BAR_H}" '
                f'fill="{VCOLOR[v]}" data-tip="{esc(VLABEL[v])}: {n:,} ({pct:.1f}% of '
                f'{total:,} attempted {esc(sev)})"/>'
            )
            if wpx > 52 and pct >= 8:  # in-segment label only when it fits
                ink = "#ffffff" if v in ("CONFIRMED",) else "#0b0b0b"
                parts.append(
                    f'<text x="{sx + wpx / 2:.1f}" y="{y + BAR_H / 2}" text-anchor="middle" '
                    f'dominant-baseline="central" class="seglabel" fill="{ink}">{pct:.0f}%</text>'
                )
        parts.append(
            f'<text x="{label_w + plot_w + 10}" y="{y + BAR_H / 2}" dominant-baseline="central" '
            f'class="axis">n={total:,}</text>'
        )
        rows_svg.append("".join(parts))
        y += ROW_H
    svg = (
        f'<svg viewBox="0 0 {width} {y}" role="img" '
        f'aria-label="Validation verdict share by claimed severity">' + "".join(rows_svg) + "</svg>"
    )
    return svg, rows_tbl


def hbar_chart(items, width=640, label_w=230, color="var(--series-1)", fmt="{:,}"):
    """Simple single-series horizontal bars, value label at tip."""
    if not items:
        return "<p class='muted'>no data</p>"
    vmax = max(v for _, v in items) or 1
    plot_w = width - label_w - 70
    parts, y = [], 0
    for name, v in items:
        w = max(plot_w * v / vmax, 2)
        parts.append(
            f'<text x="{label_w - 10}" y="{y + BAR_H / 2}" text-anchor="end" '
            f'dominant-baseline="central" class="axis">{esc(name)}</text>'
            f'<rect class="seg" x="{label_w}" y="{y}" width="{w:.1f}" height="{BAR_H}" rx="0" '
            f'fill="{color}" data-tip="{esc(name)}: {fmt.format(v)}"/>'
            f'<path d="M {label_w + w - 0.5:.1f} {y} h -4 v {BAR_H} h 4 a 4 4 0 0 0 0 -{BAR_H} z" '
            f'fill="{color}"/>'
            f'<text x="{label_w + w + 8:.1f}" y="{y + BAR_H / 2}" dominant-baseline="central" '
            f'class="vlabel">{fmt.format(v)}</text>'
        )
        y += ROW_H - 6
    return f'<svg viewBox="0 0 {width} {y}" role="img">' + "".join(parts) + "</svg>"


def tile(label, value, note=""):
    n = f'<div class="tile-note">{esc(note)}</div>' if note else ""
    return (
        f'<div class="tile"><div class="tile-label">{esc(label)}</div>'
        f'<div class="tile-value">{esc(value)}</div>{n}</div>'
    )


def table(headers, rows, cls=""):
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        tds = "".join(f"<td>{esc(c)}</td>" for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>'


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append(
            "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |"
        )
    return "\n".join(out)


def build_markdown(v, fz, now, totals, attempted, grand, cov, stacked_tbl):
    vs = v["verdict_sev"]
    conf_crit = vs["CONFIRMED"].get("critical", 0)
    conf_high = vs["CONFIRMED"].get("high", 0)
    lines = [
        "# Live Validation & Fuzzing — Portfolio Summary",
        "",
        f"**Generated:** {now}  ",
        f"**Sources:** `validations/` ({v['reports']:,} live-validation reports) · "
        f"`FUZZ-CAMPAIGN-SUMMARY.md`{_tracking_suffix(' · ')}",
        "",
        "## Headline",
        "",
        f"**{totals['CONFIRMED']:,} findings confirmed exploitable** in live environments "
        f"({conf_crit:,} claimed-Critical, {conf_high:,} claimed-High) · "
        f"**{totals['REFUTED']:,} refuted** (removed as false positives) · "
        f"{attempted:,} of {grand:,} finding-checks attempted ({cov:.1f}% coverage) · "
        f"{v['chains_live']:,} of {v['chains_total']:,} mapped attack chains have ≥1 confirmed step.",
        "",
        "## Verdicts by claimed severity",
        "",
        md_table(
            ["Claimed severity"] + [VLABEL[vd] for vd in VERDICTS] + ["Attempted", "Not attempted"],
            [
                [name]
                + [f"{c:,}" for c in counts]
                + [f"{tot:,}", f"{v['na_sev'].get(name.lower(), 0):,}"]
                for name, counts, tot in stacked_tbl
            ],
        ),
        "",
        "## Top targets by confirmed findings",
        "",
        md_table(
            ["Target", "Confirmed", "Confirmed Critical"],
            [
                (t, f"{n:,}", f"{v['per_target_crit'].get(t, 0):,}")
                for t, n in v["per_target"].most_common(15)
            ],
        ),
        "",
        "## Offline fuzz campaign",
        "",
        f"{fz['totals'].get('targets', '—')} targets · {fz['totals'].get('fuzzers', '—')} fuzzers · "
        f"≥{fz['totals'].get('bugs', '—')} confirmed bugs · "
        f"{fz['totals'].get('advisories', '—')} portfolio advisories.",
        "",
        "### Pattern hit-rate",
        "",
        md_table(
            ["Pattern", "Vulnerable / tested", "Advisory"],
            [
                (p["name"], f"{p['vuln']}/{p['tested']}", p["advisory"] or "—")
                for p in fz["patterns"]
            ],
        ),
        "",
        "### Confirmed fuzz bugs (severity-ranked)",
        "",
        md_table(["#", "Repo", "Bug", "CVSS", "CWE", "Advisory"], fz["bugs"]),
        "",
        "## Confirmed Critical findings (live-validated, first 25)",
        "",
        md_table(
            ["Target", "Finding", "Observed impact"],
            [
                (t, ti, (im[:110] + "…") if len(im) > 110 else im)
                for t, ti, im in sorted(v["confirmed_crit"], key=lambda r: r[0])[:25]
            ],
        ),
        "",
        f"*{len(v['confirmed_crit']):,} confirmed-Critical validations total. "
        "Full interactive version: `Live-validation-fuzz-dashboard.html`.*",
        "",
    ]
    return "\n".join(lines)


# --- shared metrics ledger (best-effort; dashboards never fail on it) -------


def _ledger_soft(config_home):
    try:
        import importlib

        mod = importlib.import_module("traust_engine.metrics.history")
        ws = workspace_dir(load_engine(config_home))
        return mod, ws
    except SystemExit:
        return None, None
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


# --- standard population block (traust.cli.groups.corpus; best-effort) ------------


def _population_lines(counts):
    """Markdown lines of the standard population block, [] if corpus.py is
    unavailable — the dashboard must render either way."""
    try:
        import importlib

        corpus = importlib.import_module("traust_engine.corpus.resolver")
        cfg = corpus.load_config()
        roots = corpus.roots_description(
            cfg,
            None,
            extra=[
                "`validations/*/` (live-validation verdicts)",
                "`FUZZ-CAMPAIGN-SUMMARY.md` (offline fuzz results)",
            ],
        )
        return corpus.population_block_lines(
            tool="validation-fuzz-dashboard",
            roots=roots,
            unit="per-finding live-validation verdicts (CONFIRMED/REFUTED/"
            "INCONCLUSIVE/BLOCKED_BY_SCOPE/NOT_ATTEMPTED) + attack "
            "chains",
            filters="NOT_ATTEMPTED excluded from coverage %; REFUTED = removed false positives",
            denominator="directory walk of validations/*/ for *validation*.json",
            counts=counts,
        )
    except Exception as e:
        print(f"[!] population block omitted: {e}", file=sys.stderr)
        return []


def _population_html(lines):
    """Render the population block lines as a final HTML panel."""
    if not lines:
        return ""
    lis = []
    for ln in lines:
        if not ln.startswith("- "):
            continue  # heading/blank handled by the <h2> below
        t = esc(ln[2:])
        t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        lis.append(f"<li>{t}</li>")
    return (
        '\n<h2>Population</h2>\n<div class="card"><ul style="margin:0;'
        "padding-left:18px;color:var(--text-2);font-size:12.5px;"
        'line-height:1.8">' + "".join(lis) + "</ul></div>\n"
    )


def build(root, out_path, out_md=None, config_home=None):
    v = scan_validations(root)
    fz = scan_fuzz(root)
    now = datetime.date.today().isoformat()

    vs = v["verdict_sev"]
    totals = {vd: sum(vs[vd].values()) for vd in VERDICTS}
    attempted = sum(totals.values())
    grand = attempted + v["not_attempted"]
    cov = 100.0 * attempted / grand if grand else 0.0
    confirmed = totals["CONFIRMED"]
    conf_crit = vs["CONFIRMED"].get("critical", 0)
    conf_high = vs["CONFIRMED"].get("high", 0)

    stacked_svg, stacked_tbl = stacked_bar_rows(vs)
    top_targets = hbar_chart(v["per_target"].most_common(12))
    pat_items = [
        (
            f"{p['name'][:44]} ({p['vuln']}/{p['tested']})",
            round(100.0 * p["vuln"] / p["tested"]) if p["tested"] else 0,
        )
        for p in fz["patterns"]
    ]
    pat_chart = hbar_chart(pat_items, label_w=330, fmt="{}%")

    legend = "".join(
        f'<span class="key"><span class="swatch" style="background:{VCOLOR[vd]}"></span>{esc(VLABEL[vd])}</span>'
        for vd in VERDICTS
    )
    stacked_table = table(
        ["Claimed severity"] + [VLABEL[vd] for vd in VERDICTS] + ["Attempted", "Not attempted"],
        [
            [name]
            + [f"{c:,}" for c in counts]
            + [f"{tot:,}", f"{v['na_sev'].get(name.lower(), 0):,}"]
            for name, counts, tot in stacked_tbl
        ],
        cls="num",
    )
    crit_rows = sorted(v["confirmed_crit"], key=lambda r: r[0])[:25]
    fuzz_bug_tbl = table(["#", "Repo", "Bug", "CVSS", "CWE", "Advisory"], fz["bugs"], cls="num")
    top_tbl = table(
        ["Target", "Confirmed findings", "Confirmed criticals"],
        [
            (t, f"{n:,}", f"{v['per_target_crit'].get(t, 0):,}")
            for t, n in v["per_target"].most_common(25)
        ],
        cls="num",
    )

    pop_lines = _population_lines(
        {
            "Validation reports parsed": f"{v['reports']:,}",
            "Finding-checks attempted": f"{attempted:,} / {grand:,} ({cov:.1f}% coverage)",
            "Confirmed": f"{confirmed:,}",
            "Refuted": f"{totals['REFUTED']:,}",
        }
    )
    pop_html = _population_html(pop_lines)

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Live Validation &amp; Fuzzing — Portfolio Dashboard</title>
<style>
.viz-root {{
  --surface-1:#fcfcfb; --page:#f9f9f7; --text-1:#0b0b0b; --text-2:#52514e;
  --muted:#898781; --grid:#e1e0d9; --border:rgba(11,11,11,.10);
  --series-1:#2a78d6; --good:#0ca30c;
}}
@media (prefers-color-scheme: dark) {{ .viz-root {{
  --surface-1:#1a1a19; --page:#0d0d0d; --text-1:#ffffff; --text-2:#c3c2b7;
  --muted:#898781; --grid:#2c2c2a; --border:rgba(255,255,255,.10);
  --series-1:#3987e5; --good:#0ca30c;
}} }}
body{{margin:0;background:var(--page);color:var(--text-1);
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
.viz-root{{max-width:1080px;margin:0 auto;padding:28px 20px 60px;background:var(--page)}}
h1{{font-size:22px;font-weight:650;margin:0 0 2px}}
h2{{font-size:16px;font-weight:600;margin:34px 0 4px}}
.sub,.muted{{color:var(--text-2);font-size:13px}} .muted{{color:var(--muted)}}
.card{{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;
  padding:18px 20px;margin-top:12px}}
.hero-label{{color:var(--text-2);font-size:13px}}
.hero{{font-size:52px;font-weight:650;line-height:1.1}}
.hero-note{{color:var(--text-2);font-size:13px;margin-top:2px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:12px}}
.tile{{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:12px 14px}}
.tile-label{{color:var(--text-2);font-size:12px}}
.tile-value{{font-size:24px;font-weight:650;margin-top:2px}}
.tile-note{{color:var(--muted);font-size:11.5px;margin-top:2px}}
svg{{width:100%;height:auto;display:block;margin-top:10px}}
svg text.axis{{fill:var(--text-2);font:12px system-ui,sans-serif}}
svg text.vlabel{{fill:var(--text-1);font:12px system-ui,sans-serif;font-variant-numeric:tabular-nums}}
svg text.seglabel{{font:11px system-ui,sans-serif}}
.legend{{margin-top:10px;color:var(--text-2);font-size:12.5px;display:flex;gap:16px;flex-wrap:wrap}}
.key{{display:inline-flex;align-items:center;gap:6px}}
.swatch{{width:12px;height:12px;border-radius:3px;display:inline-block}}
details{{margin-top:10px}} summary{{cursor:pointer;color:var(--text-2);font-size:12.5px}}
table{{border-collapse:collapse;width:100%;margin-top:8px;font-size:12.5px}}
th{{text-align:left;color:var(--text-2);font-weight:600;border-bottom:1px solid var(--grid);
  padding:6px 8px;white-space:nowrap}}
td{{border-bottom:1px solid var(--grid);padding:6px 8px;vertical-align:top}}
table.num td:nth-child(n+2){{font-variant-numeric:tabular-nums}}
#tip{{position:fixed;pointer-events:none;background:var(--surface-1);color:var(--text-1);
  border:1px solid var(--border);border-radius:8px;padding:7px 10px;font-size:12.5px;
  box-shadow:0 4px 14px rgba(0,0,0,.15);display:none;z-index:9;max-width:340px}}
#tip b{{font-size:13px}}
rect.seg:hover{{filter:brightness(1.12)}}
.meter{{height:10px;border-radius:5px;background:color-mix(in srgb,var(--series-1) 18%,var(--surface-1));
  overflow:hidden;margin-top:8px}}
.meter>div{{height:100%;background:var(--series-1);border-radius:5px}}
footer{{margin-top:40px;color:var(--muted);font-size:12px}}
</style></head><body><div class="viz-root">
<h1>Live Validation &amp; Fuzzing — Portfolio Dashboard</h1>
<div class="sub">Generated {now} · sources: <code>validations/</code> ({v["reports"]} live-validation reports)
 &amp; <code>FUZZ-CAMPAIGN-SUMMARY.md</code>{_tracking_suffix(" · ")}</div>

<div class="card">
  <div class="hero-label">Findings confirmed exploitable in live environments</div>
  <div class="hero">{confirmed:,}</div>
  <div class="hero-note">{conf_crit:,} claimed-Critical and {conf_high:,} claimed-High findings reproduced
   against running operators · {totals["REFUTED"]:,} findings refuted (removed as false positives)</div>
</div>

<div class="tiles">
{tile("Validation targets", f"{v['reports']:,}", "operator/product deployments")}
{tile("Findings attempted", f"{attempted:,}", f"{cov:.1f}% of {grand:,} finding-checks")}
{tile("Refuted (false positives)", f"{totals['REFUTED']:,}")}
{tile("Attack chains with a confirmed step", f"{v['chains_live']:,}", f"of {v['chains_total']:,} mapped")}
{tile("Fuzz targets", fz["totals"].get("targets", "—"), f"{fz['totals'].get('fuzzers', '—')} fuzzers")}
{tile("Fuzz bugs confirmed", "≥" + fz["totals"].get("bugs", "—"), f"{fz['totals'].get('advisories', '—')} portfolio advisories")}
</div>

<h2>Verdicts by claimed severity</h2>
<div class="sub">Share of attempted validations per severity — not-attempted findings excluded (coverage below).</div>
<div class="card">
  {stacked_svg}
  <div class="legend">{legend}</div>
  <details><summary>Table view</summary>{stacked_table}</details>
</div>

<h2>Validation coverage</h2>
<div class="card">
  <div class="sub">{attempted:,} of {grand:,} finding-checks attempted ({cov:.1f}%). The remainder is
   NOT_ATTEMPTED — mostly lower-severity findings outside engagement scope.</div>
  <div class="meter"><div style="width:{cov:.1f}%"></div></div>
</div>

<h2>Top targets by confirmed findings</h2>
<div class="card">
  {top_targets}
  <details><summary>Table view (top 25)</summary>{top_tbl}</details>
</div>

<h2>Offline fuzz campaign</h2>
<div class="sub">2026-07-02 → 07-04 · Go-native <code>go test -fuzz</code> against audit-named target functions.</div>
<div class="card">
  <h2 style="margin-top:0">Pattern hit-rate (share of tested targets vulnerable)</h2>
  {pat_chart}
  <details open><summary>Confirmed fuzz bugs (severity-ranked)</summary>{fuzz_bug_tbl}</details>
</div>

<h2>Confirmed Critical findings (live-validated)</h2>
<div class="card">
{table(["Target", "Finding", "Observed impact"], [(t, ti, (im[:110] + "…") if len(im) > 110 else im) for t, ti, im in crit_rows])}
<div class="muted">First 25 of {len(v["confirmed_crit"])} confirmed-Critical validations, alphabetical by target.</div>
</div>
{pop_html}
<footer>Built by <code>traust/harnessing/validation-fuzz-dashboard/scripts/build_validation_fuzz_dashboard.py</code> —
 verdicts from live validation reports; fuzz results from the offline campaign summary.
 Tooltips supplement the table views; every value is reachable without hover.</footer>
</div>
<div id="tip"></div>
<script>
const tip = document.getElementById('tip');
document.querySelectorAll('rect.seg').forEach(r => {{
  r.addEventListener('pointermove', e => {{
    tip.style.display = 'block';
    tip.textContent = '';
    const t = r.getAttribute('data-tip') || '';
    const i = t.indexOf(':');
    const b = document.createElement('b');
    b.textContent = i > 0 ? t.slice(i + 1).trim() : t;
    tip.appendChild(b);
    if (i > 0) {{
      tip.appendChild(document.createElement('br'));
      tip.appendChild(document.createTextNode(t.slice(0, i)));
    }}
    tip.style.left = Math.min(e.clientX + 14, innerWidth - 360) + 'px';
    tip.style.top = (e.clientY + 14) + 'px';
  }});
  r.addEventListener('pointerleave', () => tip.style.display = 'none');
}});
</script></body></html>"""
    with Path(out_path).open("w", encoding="utf-8") as f:
        f.write(page)
    md = build_markdown(v, fz, now, totals, attempted, grand, cov, stacked_tbl)
    if pop_lines:
        md += "\n---\n\n" + "\n".join(pop_lines) + "\n"
    out_md = out_md or (Path(out_path).stem + ".md")
    with Path(out_md).open("w", encoding="utf-8") as f:
        f.write(md)
    print(
        f"[+] {v['reports']} validation reports · verdicts: "
        + ", ".join(f"{vd}={totals[vd]:,}" for vd in VERDICTS)
        + f", NOT_ATTEMPTED={v['not_attempted']:,}"
    )
    print(f"[+] fuzz: {len(fz['bugs'])} confirmed bugs, {len(fz['patterns'])} patterns")
    ml, _ws = _ledger_soft(config_home)
    if ml:
        headline = {
            "confirmed_exploitable": confirmed,
            "refuted": totals.get("REFUTED"),
            "checks_attempted": attempted,
            "chains_confirmed": v.get("chains_live"),
            "fuzz_bugs": int(b)
            if str(b := (fz.get("totals") or {}).get("bugs", "")).isdigit()
            else None,
        }
        prev = ml.previous("validation-fuzz")
        tline = ml.trend_line(
            headline,
            prev,
            ["confirmed_exploitable", "refuted", "checks_attempted", "chains_confirmed"],
        )
        if tline:
            _inject_trend(out_path, tline)
            _inject_trend(out_md, tline)
        if ml.append_if_changed("validation-fuzz", headline):
            print("[+] metrics snapshot appended (validation-fuzz)")

    print(f"[+] wrote {out_path}")
    print(f"[+] wrote {out_md}")


def _dashboards_home(config_home):
    try:
        engine = load_engine(config_home)
        dashboards = progress_tracker_dir(engine) / "metrics" / "dashboards"
        dashboards.mkdir(parents=True, exist_ok=True)
        return dashboards
    except SystemExit:
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (default: $AUDIT_RESULTS_ROOT or locations.yaml)",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="output path (default: <results-root>/Live-validation-fuzz-dashboard.html)",
    )
    ap.add_argument(
        "--out-md", default=None, help="markdown output path (default: same stem as --out with .md)"
    )
    args = ap.parse_args(argv)
    results = resolve_results_root(args)
    dash = _dashboards_home(args.config_home)
    out = args.out or str((dash or results) / "Live-validation-fuzz-dashboard.html")
    build(results, out, args.out_md, config_home=args.config_home)
    return 0


if __name__ == "__main__":
    sys.exit(main())
