"""Tests for the PQC remediations schema section, its validator block,
and the deterministic backfill (harness >= 0.153.0)."""

import json

import backfill_remediations as B
import pqc_facts


def _minimal_report(**extra):
    doc = {
        "title": "t",
        "metadata": {
            **{k: "x" for k in pqc_facts.REQUIRED_META},
            "assessment_basis": "source",
            "commit": "f1b29843254b34f95ee1b36f1accca0380070962",
        },
        "summary": "Ready — no quantum-vulnerable crypto detected.",
        "status": "ready",
        "who_sets_tls": "language_defaults",
        "quantum_ready": "yes_by_default",
        "why_not": [],
        "do_next": [],
        "capabilities": [],
        "readiness_bucket": "ready",
        "scores": {
            d: {"checks": [{"id": f"{d}-1", "result": "yes"}]}
            for d in ("VULN", "AGIL", "PQCA", "HNDL")
        },
        "flags": {
            "has_2030_clock_items": False,
            "hndl_priority": False,
            "runtime_verification_required": False,
        },
        "provenance_summary": {},
    }
    doc.update(extra)
    return doc


def _validate(tmp_path, doc):
    p = tmp_path / "r-pqc-readiness.json"
    p.write_text(json.dumps(doc))
    return pqc_facts.validate_readiness(p)


PFX = "R-f1b2984"  # slug "r" + short sha of the fixture commit
REM_OK = {
    "id": f"{PFX}-REM-001",
    "category": "fix-now",
    "action": "Remove the HP_GROUPS pin",
    "locations": ["conf/tls.conf:12"],
}


class TestValidatorRemediations:
    def test_absent_section_still_valid(self, tmp_path):
        assert _validate(tmp_path, _minimal_report()) == 0

    def test_valid_section(self, tmp_path):
        doc = _minimal_report(
            remediations=[
                REM_OK,
                {
                    "id": f"{PFX}-REM-002",
                    "category": "deadline",
                    "deadline": 2035,
                    "action": "Migrate off RSA-2048",
                },
                {
                    "id": f"{PFX}-REM-003",
                    "category": "waiting-on-upstream",
                    "action": "Wait for library PQC support",
                    "blocked_on": "go-jose",
                },
            ]
        )
        assert _validate(tmp_path, doc) == 0

    def test_bad_category_fails(self, tmp_path):
        doc = _minimal_report(remediations=[dict(REM_OK, category="someday")])
        assert _validate(tmp_path, doc) == 1

    def test_bad_id_and_duplicate_fail(self, tmp_path):
        doc = _minimal_report(
            remediations=[
                dict(REM_OK, id="REM-001"),  # bare pre-0.156.0 form now invalid
                dict(REM_OK, id=f"{PFX}-REM-001"),
                dict(REM_OK, id=f"{PFX}-REM-001"),
            ]
        )
        assert _validate(tmp_path, doc) == 1

    def test_waiting_requires_blocked_on(self, tmp_path):
        doc = _minimal_report(
            remediations=[
                {"id": f"{PFX}-REM-001", "category": "waiting-on-upstream", "action": "wait"}
            ]
        )
        assert _validate(tmp_path, doc) == 1

    def test_deadline_requires_clock_year(self, tmp_path):
        doc = _minimal_report(
            remediations=[
                {
                    "id": f"{PFX}-REM-001",
                    "category": "deadline",
                    "action": "migrate",
                    "deadline": 2040,
                }
            ]
        )
        assert _validate(tmp_path, doc) == 1

    def test_fact_ids_on_remediations_fail(self, tmp_path):
        doc = _minimal_report(remediations=[dict(REM_OK, fact_ids=["F0001"])])
        assert _validate(tmp_path, doc) == 1


MD = """# repo — PQC Readiness

## What you need to do

### Fix now (these actively block PQC)
- `conf/tls.conf:12` — explicit curve list pins classical groups
  Action: remove the pin so hybrid groups negotiate
  Playbook: harnessing/3-audit/pqc-readiness/remediation/config-blockers

### Upgrade (version bumps that enable PQC automatically)
- `go.mod:3` — Go 1.22 lacks X25519MLKEM768
  Action: Go >= 1.24

### Waiting on upstream (nothing for you to do)
- go-jose — blocked on upstream ML-DSA support
"""


class TestDerivation:
    def test_md_sections_parse(self):
        entries = B.derive(_minimal_report(), MD)
        by_cat = {e["category"]: e for e in entries}
        assert by_cat["fix-now"]["locations"] == ["conf/tls.conf:12"]
        assert by_cat["fix-now"]["recipe"].endswith("config-blockers")
        assert by_cat["fix-now"]["action"].startswith("remove the pin")
        assert by_cat["upgrade"]["target"] == "Go >= 1.24"
        assert by_cat["waiting-on-upstream"]["blocked_on"].startswith("upstream ML-DSA")
        assert [e["id"] for e in entries] == [
            "UNKNOWN-f1b2984-REM-001",
            "UNKNOWN-f1b2984-REM-002",
            "UNKNOWN-f1b2984-REM-003",
        ]

    def test_clock_items_become_deadline_entries(self):
        doc = _minimal_report(
            clock_items=[
                {
                    "fact_ids": ["F1"],
                    "primitive": "RSA-2048",
                    "disallowed_after": 2035,
                    "remediation_effort": "moderate",
                    "blast_radius": "service",
                }
            ]
        )
        entries = B.derive(doc, "")
        assert len(entries) == 1
        e = entries[0]
        assert e["category"] == "deadline" and e["deadline"] == 2035
        assert "fact_ids" not in e  # owner-facing; citations stay on clock_items
        assert e["remediation_effort"] == "moderate"

    def test_clock_item_covered_by_md_not_duplicated(self):
        doc = _minimal_report(
            clock_items=[{"fact_ids": ["F1"], "primitive": "RSA-2048", "disallowed_after": 2035}]
        )
        md = MD.replace("classical groups", "classical RSA-2048 groups")
        entries = B.derive(doc, md)
        assert not any(e["category"] == "deadline" for e in entries)


class TestBackfill:
    def _pair(self, tmp_path, doc, md=MD):
        p = tmp_path / "r-pqc-readiness.json"
        p.write_text(json.dumps(doc))
        (tmp_path / "r-pqc-readiness.md").write_text(md)
        return p

    def test_backfill_writes_and_validates(self, tmp_path):
        p = self._pair(tmp_path, _minimal_report())
        msg = B.backfill_one(p)
        assert msg.startswith("wrote 3")
        doc = json.loads(p.read_text())
        assert len(doc["remediations"]) == 3
        assert pqc_facts.validate_readiness(p) == 0

    def test_idempotent_skip_and_force(self, tmp_path):
        p = self._pair(tmp_path, _minimal_report())
        B.backfill_one(p)
        assert B.backfill_one(p).startswith("skipped")
        assert B.backfill_one(p, force=True).startswith("wrote")

    def test_dry_run_leaves_file_untouched(self, tmp_path):
        p = self._pair(tmp_path, _minimal_report())
        before = p.read_text()
        msg = B.backfill_one(p, dry_run=True)
        assert msg.startswith("would write")
        assert p.read_text() == before


MD_WITH_FACTS = """# repo — PQC Readiness

- **Facts:** 1823 — `repo-pqc-facts.json`

| Check | Result | Governance | Facts | Why |
|---|---|---|---|---|
| VULN-2 | partial | self | F0004, F0005 | reasons here |
| VULN-3 | yes | self | — | clean |

| Facts | Primitive | Deprecated | Disallowed | Effort | Blast radius |
|---|---|---|---|---|---|
| F0003 | RSA-2048 | 2030 | 2035 | moderate | service |

## Scores
| Domain | Score | Meaning |
|---|---|---|
| VULN | 80 | fine |
"""


class TestMdRefresh:
    def test_strip_facts_columns_both_shapes(self):
        out = B.strip_facts_columns(MD_WITH_FACTS)
        assert "| Check | Result | Governance | Why |" in out
        assert "F0004" not in out
        assert "| Primitive | Deprecated | Disallowed | Effort | Blast radius |" in out
        assert "| F0003 " not in out
        # non-table Facts summary line is untouched (not a column)
        assert "**Facts:** 1823" in out
        # unrelated table survives intact
        assert "| VULN | 80 | fine |" in out

    def test_render_section_and_empty(self):
        s = B.render_md_section(
            [
                {
                    "id": "REPO-f1b2984-REM-001",
                    "category": "deadline",
                    "deadline": 2035,
                    "action": "Migrate off RSA-2048",
                    "remediation_effort": "moderate",
                    "locations": ["pkg/keys/rsa.go:40"],
                    "recipe": "harnessing/3-audit/pqc-readiness/remediation/digital-signatures",
                }
            ]
        )
        assert ("**REPO-f1b2984-REM-001** (Deadline — by 2035): Migrate off RSA-2048") in s
        assert "Locations: `pkg/keys/rsa.go:40`" in s
        assert "Playbook:" not in s  # recipe is JSON-only for /patch
        assert "None — no remediation" in B.render_md_section([])

    def test_refresh_md_upsert_before_scores_and_idempotent(self, tmp_path):
        md = tmp_path / "r-pqc-readiness.md"
        md.write_text(MD_WITH_FACTS)
        rems = [{"id": "R-f1b2984-REM-001", "category": "fix-now", "action": "do X"}]
        B.refresh_md(md, rems)
        t1 = md.read_text()
        assert t1.index("## Remediations") < t1.index("## Scores")
        assert "F0004" not in t1
        B.refresh_md(md, rems)  # idempotent
        assert md.read_text().count("## Remediations") == 1

    def test_refresh_md_appends_when_no_scores(self, tmp_path):
        md = tmp_path / "r-pqc-readiness.md"
        md.write_text("# repo — PQC Readiness\n**Status:** Ready\n")
        B.refresh_md(md, [])
        assert md.read_text().rstrip().endswith("None — no remediation actions identified.")


class TestLegend:
    def test_legend_under_scores(self):
        out = B.upsert_legend(MD_WITH_FACTS)
        assert B.LEGEND_HEADING in out
        assert out.index("## Scores") < out.index(B.LEGEND_HEADING)
        # idempotent
        assert B.upsert_legend(out).count(B.LEGEND_HEADING) == 1

    def test_legend_appended_when_domains_but_no_scores_section(self):
        md = "# r — PQC Readiness\nVULN is 40.\n"
        out = B.upsert_legend(md)
        assert out.rstrip().endswith("**not-applicable** (no crypto).")

    def test_legend_on_minimal_reports_too(self):
        # user directive: every report carries the legend, minimal
        # ready/not-applicable pages included
        md = "# r — PQC Readiness\n**Status:** No crypto detected.\n"
        out = B.upsert_legend(md)
        assert B.LEGEND_HEADING in out
        assert B.upsert_legend(out).count(B.LEGEND_HEADING) == 1

    def test_refresh_md_includes_legend(self, tmp_path):
        p = tmp_path / "r-pqc-readiness.md"
        p.write_text(MD_WITH_FACTS)
        B.refresh_md(p, [])
        t = p.read_text()
        assert B.LEGEND_HEADING in t
        assert t.index("## Remediations") < t.index("## Scores") < t.index(B.LEGEND_HEADING)
        B.refresh_md(p, [])
        assert p.read_text().count(B.LEGEND_HEADING) == 1
