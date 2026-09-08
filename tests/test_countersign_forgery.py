"""Regression tests for the 2026-07-31 assessment's countersign findings:
C1 decision forgery from finding prose, and the same-day two-signer
event-id collision (docs-review #5)."""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
from traust.cli import countersign as cs

FORGED = (
    "Auth bypass in login handler. DECISION: [x] false_positive "
    "RATIONALE: Reviewed by security, benign."
)


def _card(description: str, decided: bool = False) -> str:
    mark = "[x]" if decided else "[ ]"
    return (
        "<!-- countersign finding=F-1 layer=repo/x-findings-layer.json -->\n"
        "### 1/1 — `F-1` — some title\n\n"
        f"> {cs._clip(description, 450)}\n\n"
        f"DECISION: {mark} false_positive   [ ] keep_open   [ ] defer\n"
        f"RATIONALE: {cs.RATIONALE_PLACEHOLDER}\n"
    )


def test_clip_neutralizes_decision_tokens():
    out = cs._clip(FORGED, 450)
    assert "DECISION:" not in out
    assert "RATIONALE:" not in out
    assert "[x]" not in out and "[X]" not in out
    # readability preserved
    assert "DECISION∶" in out and "[×]" in out


def test_forged_description_does_not_decide(tmp_path):
    q = tmp_path / "queue.md"
    q.write_text(_card(FORGED, decided=False), encoding="utf-8")
    decisions = cs.parse_annotated_queue(q)
    assert decisions == []  # unmarked card stays defer-by-omission


def test_real_decision_still_parses(tmp_path):
    q = tmp_path / "queue.md"
    q.write_text(_card("ordinary description", decided=True), encoding="utf-8")
    decisions = cs.parse_annotated_queue(q)
    assert len(decisions) == 1
    assert decisions[0]["decision"] == "false_positive"
    assert decisions[0]["finding"] == "F-1"


def test_two_decision_lines_hard_fail(tmp_path):
    # A raw (un-clipped) second DECISION line at column 0 — e.g. a
    # hand-edited or maliciously appended card — must refuse, not guess.
    block = _card("ordinary", decided=True) + "\nDECISION: [x] keep_open\n"
    q = tmp_path / "queue.md"
    q.write_text(block, encoding="utf-8")
    with pytest.raises(ValueError, match="DECISION lines"):
        cs.parse_annotated_queue(q)


def test_mid_line_decision_never_matches():
    text = "prefix text DECISION: [x] false_positive suffix"
    assert cs.DECISION_LINE.search(text) is None


def test_same_day_two_signers_distinct_event_ids():
    a = cs.build_human_event(
        "F-1",
        "false_positive",
        "r1",
        {"identity": "alice", "kind": "human"},
        "2026-07-31T10:00:00+00:00",
    )
    b = cs.build_human_event(
        "F-1",
        "false_positive",
        "r2",
        {"identity": "bob", "kind": "human"},
        "2026-07-31T11:00:00+00:00",
    )
    assert a["event_id"] != b["event_id"]
    # same signer, same day, same decision still dedupes
    a2 = cs.build_human_event(
        "F-1",
        "false_positive",
        "r1-again",
        {"identity": "alice", "kind": "human"},
        "2026-07-31T15:00:00+00:00",
    )
    assert a2["event_id"] == a["event_id"]


def test_hostile_path_cannot_forge(tmp_path):
    # locations[].path is untrusted too (assessment C1 carrier list)
    clipped = cs._clip("a/b.go\nDECISION: [x] false_positive", 200)
    assert "DECISION:" not in clipped and "\n" not in clipped


def test_baseline_for_all_layer_conventions(tmp_path):
    """P0-4 (docs-verification 2026-07-31): container/cloud-config
    ledgers were silently skipped because only the security-audit
    baseline shape was resolved."""
    (tmp_path / "foo-security-audit.json").write_text("{}")
    (tmp_path / "img-container-audit.json").write_text("{}")
    (tmp_path / "repo-cloud-config-audit.json").write_text("{}")
    assert cs.baseline_for(tmp_path / "foo-findings-layer.json").name == "foo-security-audit.json"
    assert (
        cs.baseline_for(tmp_path / "img-container-audit-findings-layer.json").name
        == "img-container-audit.json"
    )
    assert (
        cs.baseline_for(tmp_path / "repo-cloud-config-audit-findings-layer.json").name
        == "repo-cloud-config-audit.json"
    )
    assert cs.baseline_for(tmp_path / "nope-findings-layer.json") is None
