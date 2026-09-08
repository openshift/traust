"""Tests for the fuzz ledger emitter (fuzz plan step 3)."""

import importlib.util
import json

import pytest

from traust.paths import skill_dir

_SRC = skill_dir("create-fuzzing") / "scripts" / "emit_fuzz_events.py"
_spec = importlib.util.spec_from_file_location("emit_fuzz_events", _SRC)
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)


def _corpus(tmp_path, layers, repro=()):
    root = tmp_path / "corpus"
    for rel in layers:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"events": [], "metadata": {}}), encoding="utf-8")
    for rel in repro:
        (root / rel).mkdir(parents=True, exist_ok=True)
    return root


def _inputs(target_id="svc", repo="https://github.com/org/svc", audit_ref="", num=1, method="fuzz"):
    summary = {
        "bugs": [
            {
                "num": num,
                "target": target_id,
                "title": "boom",
                "cvss": "~7.5",
                "cwe": "125",
                "advisory": "",
                "method": method,
            }
        ]
    }
    targets = {
        "targets": [
            {
                "id": target_id,
                "repo": repo,
                "commit": "HEAD",
                "audit_ref": audit_ref,
                "harnesses": [],
            }
        ]
    }
    return summary, targets


def test_only_fuzz_found_bugs_are_emitted(tmp_path):
    """Static-review and grep-sweep bugs are other lanes' provenance (D3)."""
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(method="static scout")
    rows, amb, probs = E.plan(s, t, c, "sum.json", "0")
    assert rows == [] and amb == [] and probs == []


def test_clean_find_id_attaches_and_carries_no_finding(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="FIND-019")
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert len(rows) == 1
    assert rows[0]["mode"] == "attach"
    assert rows[0]["finding_ref"] == "FIND-019"
    assert "finding" not in rows[0]["event"]


def test_prose_audit_ref_carries_a_new_finding(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="see the batch-3 writeup")
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert rows[0]["mode"] == "carry"
    assert rows[0]["event"]["finding"]["origin"] == "create-fuzzing"
    assert rows[0]["event"]["finding"]["validation_status"] == "not_verified"


def test_source_type_is_fuzz_report(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs()
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert rows[0]["event"]["source"]["type"] == "fuzz_report"
    assert rows[0]["event"]["source"]["actor"] == {"kind": "machine", "identity": "create-fuzzing"}


def test_two_crashers_on_one_finding_get_distinct_event_ids(tmp_path):
    """event_id is (source_ref, finding_ref, validity, resolution). Two bugs
    confirming the same audit finding hashed identically and one was silently
    deduped away; source.ref now names the bug record."""
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="FIND-019")
    s["bugs"].append(dict(s["bugs"][0], num=2, title="boom two"))
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    ids = [r["event"]["event_id"] for r in rows]
    assert len(rows) == 2
    assert len(set(ids)) == 2, "two crashers on one finding must not collide"


def test_ambiguous_repo_is_refused_not_guessed(tmp_path):
    """A repo audited under several products has one layer each. Picking one
    silently misfiles an append-only event."""
    c = _corpus(
        tmp_path,
        ["findings/a/svc/svc-findings-layer.json", "findings/b/svc/svc-findings-layer.json"],
    )
    s, t = _inputs()
    rows, amb, _ = E.plan(s, t, c, "sum.json", "0")
    assert rows == []
    assert len(amb) == 1 and amb[0]["count"] == 2


def test_all_layers_emits_to_every_product(tmp_path):
    c = _corpus(
        tmp_path,
        ["findings/a/svc/svc-findings-layer.json", "findings/b/svc/svc-findings-layer.json"],
    )
    s, t = _inputs()
    rows, amb, _ = E.plan(s, t, c, "sum.json", "0", all_layers=True)
    assert amb == [] and len(rows) == 2
    assert len({str(r["layer"]) for r in rows}) == 2


def test_missing_reproducer_is_stated_not_hidden(tmp_path):
    """A class-1 source type without a replayable input is a claim the ledger
    should not make silently."""
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs()
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert rows[0]["reproducers"] == []
    assert "NO reproducer" in rows[0]["event"]["rationale"]


def test_reproducer_is_recorded_as_evidence(tmp_path):
    c = _corpus(
        tmp_path, ["findings/p/svc/svc-findings-layer.json"], repro=["findings/p/svc/fuzz-corpus"]
    )
    s, t = _inputs()
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert any("fuzz-corpus" in e for e in rows[0]["event"]["evidence_refs"])
    assert "reproducer recorded" in rows[0]["event"]["rationale"]


def test_unknown_target_is_a_problem_not_a_silent_skip(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs()
    t["targets"] = []
    rows, _, probs = E.plan(s, t, c, "sum.json", "0")
    assert rows == [] and len(probs) == 1 and "not in targets.json" in probs[0]


def test_carried_finding_validates_against_the_real_schema(tmp_path):
    """The suite passed while 20 layers failed validation on a missing
    required field, because nothing checked a carried finding against
    layer.schema.json. This is that check."""
    jsonschema = pytest.importorskip("jsonschema")
    from traust_contracts import paths

    schema = json.loads((paths.schema_dir() / "layer.schema.json").read_text())
    ev_finding = schema["$defs"]["event_finding"]
    resolver_schema = dict(ev_finding)
    resolver_schema["$defs"] = schema["$defs"]

    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="prose, not a finding id")
    t["targets"][0]["harnesses"] = [
        {
            "file": "svc/x_fuzz_test.go",
            "dest": "pkg/x/x_fuzz_test.go",
            "fuzz": "FuzzX",
            "pkg": "./pkg/x",
        }
    ]
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    finding = rows[0]["event"]["finding"]
    for field in ("id", "title", "severity", "cwes", "locations", "description", "remediation"):
        assert field in finding, f"{field} is required by event_finding"
    jsonschema.Draft202012Validator(resolver_schema).validate(finding)


def test_locations_come_from_the_harness_declaration(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="prose")
    t["targets"][0]["harnesses"] = [{"dest": "pkg/x/x_fuzz_test.go", "fuzz": "FuzzX"}]
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    assert rows[0]["event"]["finding"]["locations"] == [
        {"path": "pkg/x/x_fuzz_test.go", "symbol": "FuzzX"}
    ]


def test_no_harness_dest_is_repo_scoped_not_invented(tmp_path):
    c = _corpus(tmp_path, ["findings/p/svc/svc-findings-layer.json"])
    s, t = _inputs(audit_ref="prose")
    rows, _, _ = E.plan(s, t, c, "sum.json", "0")
    loc = rows[0]["event"]["finding"]["locations"]
    assert loc[0]["path"] == "." and "repo-scoped" in loc[0]["note"]
