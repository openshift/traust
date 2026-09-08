"""Tests for traust.ops.build_critical_misses (error-correction campaign
running critical-misses report)."""

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
from traust.ops import build_critical_misses as bcm

CAMPAIGN = "scan-testing/sxs-2026-07"


def _write(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")


@pytest.fixture
def results_root(tmp_path: Path) -> Path:
    root = tmp_path / "analysis-results"
    campaign = root / CAMPAIGN

    # -- probe deltas: repo1 has 1 critical + 1 high; repo2 none critical
    _write(
        campaign / "b-lite" / "repo1-delta.json",
        {
            "slug": "repo1",
            "deltas": [
                {
                    "title": "Command injection in build task",
                    "severity": "critical",
                    "cwe": "CWE-78",
                    "file": "tasks/build.yml",
                    "line": 25,
                    "rationale": "verified",
                },
                {
                    "title": "A high finding",
                    "severity": "high",
                    "cwe": "CWE-79",
                    "file": "web/x.js",
                    "line": 1,
                },
            ],
        },
    )
    _write(
        campaign / "b-lite" / "repo2-delta.json",
        {
            "slug": "repo2",
            "deltas": [
                {
                    "title": "Only medium",
                    "severity": "medium",
                    "cwe": "CWE-1",
                    "file": "a.go",
                    "line": 2,
                }
            ],
        },
    )

    # -- triage verdict for the repo1 critical (source-fragment match)
    _write(
        campaign / "fast-track-criticals-triage.json",
        {
            "triage_completed": "2026-07-22",
            "findings": [
                {
                    "id": "f001",
                    "orig_id": "REPO1-abc1234-005",
                    "source": "b-lite/repo1-delta.json#0",
                    "title": "Command injection in build task",
                    "verdict": "true_positive",
                    "confidence": 9.0,
                    "vote_breakdown": {"true_positive": 3, "false_positive": 0},
                }
            ],
        },
    )

    # -- cve-replay: one qualifying row, two non-qualifying
    _write(
        campaign / "cve-replay" / "candidates.json",
        {
            "rows": [
                {
                    "slug": "repo3",
                    "cve": "CVE-2026-1111",
                    "severity": "critical (CVSS 9.9)",
                    "present_at_audit": True,
                    "audit_verdict": "missed",
                    "summary": "RCE via thing (CWE-502)",
                },
                {
                    "slug": "repo4",
                    "cve": "CVE-2026-2222",
                    "severity": "high",
                    "present_at_audit": True,
                    "audit_verdict": "missed",
                    "summary": "high sev — must not appear",
                },
                {
                    "slug": "repo5",
                    "cve": "CVE-2026-3333",
                    "severity": "critical",
                    "present_at_audit": False,
                    "audit_verdict": "detected",
                    "summary": "already patched at audit ref",
                },
            ]
        },
    )

    # -- slug -> report map + repo1 baseline/current (ingested, confirmed)
    findings_dir = root / "findings" / "org" / "repo1"
    _write(
        findings_dir / "repo1-security-audit.json",
        {
            "findings": [
                {
                    "id": "REPO1-abc1234-005",
                    "title": "Command injection in build task",
                    "severity": "critical",
                    "cwes": ["CWE-78"],
                    "locations": [{"path": "tasks/build.yml", "lines": "22-33"}],
                }
            ],
        },
    )
    _write(
        findings_dir / "repo1-findings-current.json",
        {
            "findings": [
                {
                    "id": "REPO1-abc1234-005",
                    "severity": "critical",
                    "validation_status": "confirmed",
                    "disposition": {"validity": "confirmed", "resolution": "open"},
                }
            ],
        },
    )
    _write(
        campaign / "b-lite-probe-sample.json",
        [
            {"slug": "repo1", "report": str(findings_dir / "repo1-findings-current.json")},
        ],
    )
    return root


def _run(results_root: Path) -> str:
    out = results_root / "CRITICAL-MISSES.md"
    rc = bcm.main(["--results-root", str(results_root), "--generated-at", "2026-07-22T00:00:00Z"])
    assert rc == 0
    return out.read_text(encoding="utf-8")


def test_report_rows_and_counts(results_root: Path):
    text = _run(results_root)

    # confirmed + ingested probe critical
    assert "Command injection in build task" in text
    assert "true_positive (3-0, conf 9.0)" in text
    assert "ingested as REPO1-abc1234-005; ledger validity: confirmed" in text
    assert "no countersign required (confirmation)" in text
    assert "`b-lite/repo1-delta.json#0`" in text

    # non-critical deltas and non-qualifying replay rows excluded
    assert "A high finding" not in text
    assert "Only medium" not in text
    assert "CVE-2026-2222" not in text
    assert "CVE-2026-3333" not in text

    # qualifying cve-replay miss, measured-not-routed
    assert "CVE-2026-1111" in text
    assert "CWE-502" in text
    assert "measured — not yet routed" in text

    # summary block
    assert "Critical delta candidates (probe + matrix): **1**" in text
    assert "Triage-confirmed true positives: **1**" in text
    assert "Ingested into baseline + disposition ledger: **1**" in text
    assert "critical misses (present_at_audit, audit_verdict=missed): **1**" in text


def test_matrix_absence_tolerated_and_future_waves_globbed(results_root: Path):
    text = _run(results_root)
    assert "No matrix delta artifacts yet" in text

    # a later wave delta file + matrix delta are picked up by the globs
    _write(
        results_root / CAMPAIGN / "b-lite" / "repo9-w2-delta.json",
        {
            "slug": "repo9",
            "deltas": [
                {
                    "title": "Wave-2 critical",
                    "severity": "critical",
                    "cwe": "CWE-89",
                    "file": "db.py",
                    "line": 7,
                }
            ],
        },
    )
    _write(
        results_root / CAMPAIGN / "matrix" / "t9-delta.json",
        {
            "slug": "matrix-repo",
            "deltas": [
                {
                    "title": "Matrix critical",
                    "severity": "critical",
                    "cwe": "CWE-22",
                    "file": "z.go",
                    "line": 3,
                }
            ],
        },
    )
    text = _run(results_root)
    assert "Wave-2 critical" in text
    assert "untriaged (awaiting fast-track)" in text
    assert "## Instrument: matrix" in text
    assert "Matrix critical" in text
    assert "Critical delta candidates (probe + matrix): **3**" in text


def test_deterministic_output(results_root: Path):
    assert _run(results_root) == _run(results_root)


def test_missing_campaign_dir_errors(tmp_path: Path, capsys):
    rc = bcm.main(["--results-root", str(tmp_path)])
    assert rc == 2
    assert "campaign dir not found" in capsys.readouterr().err


def test_generation_provenance_stamp(results_root: Path):
    text = _run(results_root)
    assert "Generated: 2026-07-22T00:00:00Z" in text
    assert "build_critical_misses.py" in text
