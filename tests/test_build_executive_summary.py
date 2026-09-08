"""Tests for the executive summary's Lens 2 distinct-vulnerability pass."""

import importlib.util
import json
import sys
from pathlib import Path

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "build_executive_summary",
    skill_dir("executive-summary-findings") / "scripts" / "build_executive_summary.py",
)
es = importlib.util.module_from_spec(_SPEC)
sys.modules["build_executive_summary"] = es
_SPEC.loader.exec_module(es)


def _report(tmp_path, rel, repo, findings, dispositioned=False):
    p = tmp_path / "findings" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "metadata": {"repository": repo},
        "executive_summary": {"severity_counts": {}},
        "findings": findings,
    }
    if dispositioned:
        data["disposition_summary"] = {}
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _finding(fid, sev, path="pkg/a.go", cwe="CWE-287", fp=None, extra=None):
    f = {
        "id": fid,
        "title": f"finding {fid}",
        "severity": sev,
        "cwes": [cwe],
        "locations": [{"path": path}],
    }
    if fp:
        f["fingerprint"] = fp
    f.update(extra or {})
    return f


def test_distinct_metrics_dedup_and_confirmations(tmp_path):
    root = str(tmp_path / "findings")
    # HEAD repo1: two findings, one carried fingerprint, one computed
    _report(
        tmp_path,
        "prodA/repo1/repo1-security-audit.json",
        "https://github.com/org/repo1",
        [
            _finding("F1", "high", fp="fp-a"),
            _finding("F2", "critical", path="pkg/b.go", cwe="CWE-79"),
        ],
    )
    # mirror product, same repo URL + same locations -> same fingerprints
    _report(
        tmp_path,
        "prodB/repo1/repo1-security-audit.json",
        "https://github.com/org/repo1",
        [_finding("F1", "high", fp="fp-a")],
    )
    # branch re-audit: one confirmation (fp-a) + one branch-only
    _report(
        tmp_path,
        "prodA/repo1__release-4.19/repo1__release-4.19-security-audit.json",
        "https://github.com/org/repo1",
        [
            _finding("B1", "high", fp="fp-a"),
            _finding("B2", "low", path="pkg/only-branch.go", cwe="CWE-20"),
        ],
    )
    # hardening + FP never enter the distinct set
    _report(
        tmp_path,
        "prodA/repo2/repo2-security-audit.json",
        "https://github.com/org/repo2",
        [
            _finding("H1", "medium", extra={"validation_status": "hardening"}),
            _finding("X1", "high", extra={"validation_status": "false_positive"}),
        ],
    )

    reports, _ = es.discover_reports([root])
    m = es.distinct_metrics(reports, [root])
    d = m["distinct"]["findings"]
    assert d["total"] == 2  # fp-a deduped across products
    assert d["open"] == 2
    assert d["by_severity"]["critical"] == 1
    assert m["branch_reports"] == 1
    assert m["branch_findings"] == 2
    assert m["branch_confirmations"] == 1
    assert m["fingerprint_coverage"] == 100.0


def _agg_with_branch(tmp_path):
    """Aggregate over a minimal HEAD + branch-re-audit fixture, ready
    for render_markdown/render_html (branch-awareness Phase 4 tests)."""
    root = str(tmp_path / "findings")
    _report(
        tmp_path,
        "prodA/repo1/repo1-security-audit.json",
        "https://github.com/org/repo1",
        [_finding("F1", "high", fp="fp-a")],
    )
    _report(
        tmp_path,
        "prodA/repo1__release-4.19/repo1__release-4.19-security-audit.json",
        "https://github.com/org/repo1",
        [_finding("B1", "high", fp="fp-a")],
    )
    reports, _ = es.discover_reports([root])
    agg = es.aggregate(reports, {}, [root])
    agg.update(es.distinct_metrics(reports, [root]))
    return agg


def test_ref_coverage_rows_render_md_and_html(tmp_path):
    agg = _agg_with_branch(tmp_path)
    agg["ref_coverage"] = {
        "refs": {"release-4.19": 3, "release-4.20": 1},
        "declared": 0,
        "reports": 5,
    }
    md = es.render_markdown(agg, ["findings/"], "0-test")
    assert "**Ref coverage**" in md
    assert "| `release-4.19` | 3 |" in md
    assert "| `release-4.20` | 1 |" in md
    html_doc = es.render_html(agg, ["findings/"], "0-test")
    assert "Ref coverage" in html_doc
    assert "<code>release-4.19</code>" in html_doc
    # ordering: count desc — 4.19 rows precede 4.20 in both outputs
    assert md.index("release-4.19") < md.index("release-4.20")


def test_ref_coverage_folds_tail_past_top_n(tmp_path):
    agg = _agg_with_branch(tmp_path)
    refs = {f"release-4.{i}": 1 for i in range(es.REF_COVERAGE_TOP_N + 3)}
    refs["release-9.9"] = 50
    agg["ref_coverage"] = {"refs": refs, "declared": 0, "reports": sum(refs.values())}
    md = es.render_markdown(agg, ["findings/"], "0-test")
    assert "| `release-9.9` | 50 |" in md  # top ref always shown
    assert "more refs_ | 4 |" in md  # 14 refs -> 10 shown + 4 folded


def test_ref_coverage_is_additive_only(tmp_path):
    """Phase-4 invariance: without ref_coverage the outputs are
    byte-identical to the pre-Phase-4 rendering; with it, existing
    lines are untouched (diff contains only insertions)."""
    import difflib

    agg = _agg_with_branch(tmp_path)
    base_md = es.render_markdown(dict(agg), ["findings/"], "0-test")
    base_html = es.render_html(dict(agg), ["findings/"], "0-test")
    # absent/None ref data -> byte-identical
    agg_none = dict(agg)
    agg_none["ref_coverage"] = None
    assert es.render_markdown(agg_none, ["findings/"], "0-test") == base_md
    assert es.render_html(agg_none, ["findings/"], "0-test") == base_html
    # present -> insert-only diff
    agg2 = dict(agg)
    agg2["ref_coverage"] = {"refs": {"release-4.19": 1}, "declared": 0, "reports": 2}
    md2 = es.render_markdown(agg2, ["findings/"], "0-test")
    html2 = es.render_html(agg2, ["findings/"], "0-test")
    assert md2 != base_md and html2 != base_html
    for old, new in ((base_md, md2), (base_html, html2)):
        ops = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines()).get_opcodes()
        assert all(tag in ("equal", "insert") for tag, *_ in ops)


def test_dedupe_prefers_fingerprint():
    entries = [
        {
            "repo": "r1",
            "title": "same bug worded one way",
            "severity": "high",
            "cvss": 8.0,
            "cwes": [],
            "resolution": None,
            "fingerprint": "fp-x",
        },
        {
            "repo": "r2",
            "title": "same bug worded another way",
            "severity": "high",
            "cvss": 7.0,
            "cwes": [],
            "resolution": None,
            "fingerprint": "fp-x",
        },
    ]
    agg = es.aggregate(
        [
            {
                "source": "findings/p/r/x-security-audit.json",
                "counts": {},
                "findings": entries,
                "repository": "https://github.com/org/r1",
            }
        ],
        {},
        ["findings"],
    )
    assert len(agg["crit_high"]) == 1  # collapsed by fingerprint
    assert agg["crit_high_raw"] == 2
