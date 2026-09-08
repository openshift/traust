#!/usr/bin/env python3
"""compile_precedent_cards.py tests — card schema validation (the
REJECT gate), predicate application against fixture enumerator
artifacts, the pinned prose-reject case, and output-shape compatibility
with sweep-candidates ingestion (/triage generic candidate shape).
All on fixtures; never runs an enumerator against a real repo."""

import json
import unittest
from pathlib import Path

from traust.ops import compile_precedent_cards as CPC
from traust.paths import skill_dir

HARNESS = Path(__file__).resolve().parents[1]
PILOT = skill_dir("mine-ledger") / "precedent-cards" / "pilot.yaml"


def valid_route_card(**over):
    card = {
        "id": "pc-test-route",
        "source_findings": [{"finding_id": "REPO-abc1234-001", "repo": "repo"}],
        "weakness_shape": "A route lacks the guard its siblings carry.",
        "enumerator": "route-guards",
        "predicate": {
            "all": [
                {"field": "judgement_required", "op": "truthy"},
                {"field": "guards", "op": "empty"},
                {"field": "scope_guards", "op": "empty"},
            ]
        },
        "judge_question": "Is the route reachable unauthenticated?",
        "expected_fp_sources": ["healthz endpoints"],
        "severity_hint": "high",
    }
    card.update(over)
    return card


def valid_config_card(**over):
    card = {
        "id": "pc-test-dsn",
        "source_findings": [{"finding_id": "REPO-abc1234-002", "repo": "repo"}],
        "weakness_shape": "A DSN default composes to plaintext.",
        "enumerator": "config-matrix",
        "predicate": {
            "all": [
                {"field": "class", "op": "eq", "value": "dsn"},
                {"field": "judgement_required", "op": "truthy"},
                {
                    "field": "effective_default",
                    "op": "matches",
                    "value": r"sslmode=disable|^postgres://",
                },
            ]
        },
        "judge_question": "Does the default reach a production path?",
        "expected_fp_sources": ["dev compose files"],
        "severity_hint": "high",
    }
    card.update(over)
    return card


# fixture artifacts — field shapes copied from the emitting scripts

ROUTE_GUARDS_ARTIFACT = {
    "artifact": "route-guard-matrix",
    "repo": "fixture-repo",
    "routes": [
        {  # guarded — must NOT match
            "family": "go-http",
            "method": "HandleFunc",
            "pattern": "/api/admin",
            "handler": {
                "expr": "requireAuth(adminHandler)",
                "path": "server/routes.go",
                "line": 10,
            },
            "guards": ["requireAuth"],
            "scope_guards": [],
            "registration": {"path": "server/routes.go", "line": 10},
            "judgement_required": False,
        },
        {  # bare sibling — MUST match
            "family": "go-http",
            "method": "HandleFunc",
            "pattern": "/api/cleanup",
            "handler": {"expr": "cleanupHandler", "path": "server/routes.go", "line": 11},
            "guards": [],
            "scope_guards": [],
            "registration": {"path": "server/routes.go", "line": 11},
            "judgement_required": True,
            "asymmetry": True,
        },
        {  # scope-guarded — must NOT match
            "family": "go-http",
            "method": "Get",
            "pattern": "/api/data",
            "handler": {"expr": "dataHandler", "path": "server/data.go", "line": 5},
            "guards": [],
            "scope_guards": ["authMiddleware"],
            "registration": {"path": "server/data.go", "line": 5},
            "judgement_required": False,
        },
    ],
    "asymmetries": [],
    "coverage_gaps": [],
    "stats": {},
}

CONFIG_MATRIX_ARTIFACT = {
    "artifact": "config-matrix",
    "repo": "fixture-repo",
    "triples": [
        {  # weak DSN default — MUST match
            "key": "database.sslmode",
            "effective_default": "sslmode=disable",
            "source": {"system": "helm", "path": "chart/values.yaml", "line": 42},
            "sink": {"status": "template", "path": "chart/templates/deploy.yaml", "line": 7},
            "class": "dsn",
            "judgement_required": True,
            "weak_default": True,
        },
        {  # secure DSN — must NOT match
            "key": "database.url",
            "effective_default": "postgresql://db:5432/app?sslmode=verify-full",
            "source": {"system": "helm", "path": "chart/values.yaml", "line": 43},
            "sink": {"status": "unresolved"},
            "class": "dsn",
            "judgement_required": True,
        },
        {  # non-dsn — must NOT match
            "key": "log.level",
            "effective_default": "info",
            "source": {"system": "helm", "path": "chart/values.yaml", "line": 44},
            "sink": {"status": "unresolved"},
            "class": "other",
            "judgement_required": False,
        },
        {  # weak DSN in test fixture path — matches, test_path=True
            "key": "TEST_DB_URL",
            "effective_default": "postgres://localhost/test",
            "source": {"system": "compose", "path": "tests/docker-compose.yaml", "line": 3},
            "sink": {"status": "service", "service": "db"},
            "class": "dsn",
            "judgement_required": True,
            "weak_default": False,
        },
    ],
    "coverage_gaps": [],
    "stats": {},
}

SANITIZER_RUN_ARTIFACT = {
    "artifact": "sanitizer-probes",
    "repo": "fixture-repo",
    "mode": "run",
    "candidates": [],
    "probes": [
        {
            "function": "sanitize_jinja",
            "path": "app/util.py",
            "line": 12,
            "arg": "value",
            "is_method": False,
            "outcome": "survived",
            "survived": 2,
            "errors": 0,
            "transcript": [],
        },
        {
            "function": "escape_html",
            "path": "app/util.py",
            "line": 40,
            "arg": "value",
            "is_method": False,
            "outcome": "neutralized",
            "survived": 0,
            "errors": 0,
            "transcript": [],
        },
    ],
}

# the generic-candidate keys sweep_engine.py `emit` writes — the
# ingestion contract /triage reads (its Note — class-generalization
# sweep candidates section)
SWEEP_CANDIDATE_KEYS = {
    "repo",
    "url",
    "file",
    "line",
    "end_line",
    "location",
    "excerpt",
    "rule_id",
    "severity_hint",
    "test_path",
    "source_finding_provenance",
}


class TestCardValidation(unittest.TestCase):
    def test_valid_cards_pass(self):
        self.assertEqual(CPC.validate_card(valid_route_card()), [])
        self.assertEqual(CPC.validate_card(valid_config_card()), [])

    def test_prose_only_card_rejected(self):
        """The 'no prose checklists' rule made mechanical: a checklist
        card with no predicate is rejected, with every reason named."""
        card = valid_route_card()
        del card["predicate"]
        card["checklist"] = ["look at all the routes"]
        errors = CPC.validate_card(card)
        self.assertTrue(any("no_predicate" in e for e in errors))
        self.assertTrue(any("prose_checklist_fields" in e for e in errors))

    def test_unknown_enumerator_rejected(self):
        card = valid_route_card(enumerator="manual-review")
        errors = CPC.validate_card(card)
        self.assertTrue(any("unknown_enumerator" in e for e in errors))

    def test_unknown_field_rejected(self):
        """A predicate over fields the enumerator never emits is prose
        in disguise — rejected."""
        card = valid_route_card(predicate={"field": "is_actually_dangerous", "op": "truthy"})
        errors = CPC.validate_card(card)
        self.assertTrue(any("is_actually_dangerous" in e for e in errors))

    def test_unknown_op_rejected(self):
        card = valid_route_card(predicate={"field": "guards", "op": "looks_suspicious"})
        errors = CPC.validate_card(card)
        self.assertTrue(any("unknown op" in e for e in errors))

    def test_bad_regex_rejected(self):
        card = valid_config_card(
            predicate={"field": "effective_default", "op": "matches", "value": "(unclosed"}
        )
        errors = CPC.validate_card(card)
        self.assertTrue(any("bad regex" in e for e in errors))

    def test_missing_required_fields_rejected(self):
        card = valid_route_card()
        del card["judge_question"]
        del card["source_findings"]
        errors = CPC.validate_card(card)
        self.assertTrue(any("judge_question" in e for e in errors))
        self.assertTrue(any("source_findings" in e for e in errors))

    def test_run_only_field_needs_execution_ack(self):
        """Predicates over probe run-mode fields require the card to
        declare enumerator_options.run: true (executing repo code is
        an explicit, sandbox-doctrine decision)."""
        card = valid_route_card(
            id="pc-test-probe",
            enumerator="sanitizer-probes",
            predicate={"field": "outcome", "op": "eq", "value": "survived"},
        )
        errors = CPC.validate_card(card)
        self.assertTrue(any("'outcome'" in e for e in errors))
        card["enumerator_options"] = {"run": True}
        self.assertEqual(CPC.validate_card(card), [])

    def test_symbol_index_requires_query(self):
        card = valid_route_card(
            id="pc-test-sym",
            enumerator="symbol-index",
            predicate={"field": "name", "op": "matches", "value": "Handler$"},
        )
        errors = CPC.validate_card(card)
        self.assertTrue(any("symbol_index_query_missing" in e for e in errors))
        card["enumerator_options"] = {"query": {"mode": "defs", "name": "Handler"}}
        self.assertEqual(CPC.validate_card(card), [])

    def test_bad_severity_hint_rejected(self):
        card = valid_route_card(severity_hint="catastrophic")
        errors = CPC.validate_card(card)
        self.assertTrue(any("severity_hint" in e for e in errors))


class TestPredicateApplication(unittest.TestCase):
    def test_route_guards_predicate(self):
        card = valid_route_card()
        rows = CPC.rows_of("route-guards", {}, ROUTE_GUARDS_ARTIFACT)
        matched = [r for r in rows if CPC.apply_predicate(card["predicate"], r)]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["pattern"], "/api/cleanup")

    def test_config_matrix_predicate(self):
        card = valid_config_card()
        rows = CPC.rows_of("config-matrix", {}, CONFIG_MATRIX_ARTIFACT)
        matched = [r for r in rows if CPC.apply_predicate(card["predicate"], r)]
        keys = {m["key"] for m in matched}
        self.assertEqual(keys, {"database.sslmode", "TEST_DB_URL"})

    def test_sanitizer_run_rows_and_predicate(self):
        pred = {
            "all": [
                {"field": "outcome", "op": "eq", "value": "survived"},
                {"field": "survived", "op": "gte", "value": 1},
            ]
        }
        rows = CPC.rows_of("sanitizer-probes", {"run": True}, SANITIZER_RUN_ARTIFACT)
        matched = [r for r in rows if CPC.apply_predicate(pred, r)]
        self.assertEqual([m["function"] for m in matched], ["sanitize_jinja"])

    def test_combinators_and_missing_fields(self):
        row = {"guards": [], "judgement_required": True}
        self.assertTrue(CPC.apply_predicate({"not": {"field": "guards", "op": "not_empty"}}, row))
        # missing field resolves to None — empty matches, truthy fails
        self.assertTrue(CPC.apply_predicate({"field": "scope_guards", "op": "empty"}, row))
        self.assertFalse(CPC.apply_predicate({"field": "scope_guards", "op": "truthy"}, row))


class TestCompileOutputShape(unittest.TestCase):
    def _report(self):
        cards = [valid_route_card(), valid_config_card()]
        for c in cards:
            self.assertEqual(CPC.validate_card(c), [])
        return CPC.compile_from_artifacts(
            cards,
            {"route-guards": ROUTE_GUARDS_ARTIFACT, "config-matrix": CONFIG_MATRIX_ARTIFACT},
            "fixture-repo",
            "dir:/tmp/fixture-repo",
        )

    def test_container_is_sweep_candidates_shape(self):
        report = self._report()
        self.assertEqual(report["artifact"], "sweep-candidates")
        self.assertEqual(report["tier"], "semantic")
        # the keys /triage's generic ingest and the sweep note rely on
        for key in (
            "purpose",
            "generated",
            "harness_version",
            "repos_swept",
            "repos_with_hits",
            "repo_errors",
            "candidates",
        ):
            self.assertIn(key, report)
        self.assertIsInstance(report["candidates"], list)

    def test_candidates_carry_sweep_engine_keys(self):
        report = self._report()
        self.assertEqual(len(report["candidates"]), 3)
        for cand in report["candidates"]:
            self.assertTrue(
                set(cand) >= SWEEP_CANDIDATE_KEYS,
                f"candidate missing sweep-engine keys: {SWEEP_CANDIDATE_KEYS - set(cand)}",
            )
            # semantic extras ride along
            self.assertEqual(cand["origin"], "semantic-sweep")
            self.assertTrue(cand["judge_question"])
            self.assertEqual(cand["rule_id"], cand["card_id"])

    def test_candidate_field_mapping(self):
        report = self._report()
        route = next(c for c in report["candidates"] if c["card_id"] == "pc-test-route")
        self.assertEqual(route["file"], "server/routes.go")
        self.assertEqual(route["line"], 11)
        self.assertEqual(route["location"], "server/routes.go:11")
        self.assertIn("/api/cleanup", route["excerpt"])
        self.assertEqual(route["source_finding_provenance"], ["REPO-abc1234-001"])
        self.assertFalse(route["test_path"])

    def test_test_path_flagged(self):
        report = self._report()
        test_hits = [c for c in report["candidates"] if c["file"] == "tests/docker-compose.yaml"]
        self.assertEqual(len(test_hits), 1)
        self.assertTrue(test_hits[0]["test_path"])

    def test_per_card_stats(self):
        report = self._report()
        stats = {c["id"]: c for c in report["cards"]}
        self.assertEqual(stats["pc-test-route"]["rows_enumerated"], 3)
        self.assertEqual(stats["pc-test-route"]["matched"], 1)
        self.assertEqual(stats["pc-test-dsn"]["matched"], 2)

    def test_report_is_json_serializable(self):
        json.dumps(self._report())


class TestPilotCards(unittest.TestCase):
    """The shipped pilot set: 4 valid cards + exactly 1 pinned reject."""

    def setUp(self):
        if CPC.yaml is None:  # pragma: no cover - environment guard
            self.skipTest("PyYAML unavailable")
        self.cards = CPC.load_cards(PILOT)

    def test_pilot_file_partition(self):
        valid, rejected = CPC.partition_cards(self.cards)
        self.assertEqual(len(valid), 4)
        self.assertEqual(len(rejected), 1)
        reject = rejected[0]
        self.assertEqual(reject["id"], "pc-REJECT-oauth-callback-prose")
        self.assertTrue(reject["expect_reject"])
        reasons = " ".join(reject["reasons"])
        self.assertIn("unknown_enumerator", reasons)
        self.assertIn("no_predicate", reasons)
        self.assertIn("prose_checklist_fields", reasons)

    def test_pilot_valid_cards_compile_against_fixtures(self):
        valid, _ = CPC.partition_cards(self.cards)
        report = CPC.compile_from_artifacts(
            valid,
            {
                "route-guards": ROUTE_GUARDS_ARTIFACT,
                "config-matrix": CONFIG_MATRIX_ARTIFACT,
                "sanitizer-probes": SANITIZER_RUN_ARTIFACT,
            },
            "fixture-repo",
            None,
        )
        stats = {c["id"]: c for c in report["cards"]}
        self.assertEqual(stats["pc-unguarded-route-class"]["matched"], 1)
        # dsn card: weak sslmode + plaintext test DSN
        self.assertEqual(stats["pc-dsn-plaintext-default"]["matched"], 2)
        self.assertEqual(stats["pc-sanitizer-bypass-survivor"]["matched"], 1)
        # every compiled card produced a judged candidate row
        for cand in report["candidates"]:
            self.assertTrue(cand["judge_question"])


if __name__ == "__main__":
    unittest.main()
