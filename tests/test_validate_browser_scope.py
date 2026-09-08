#!/usr/bin/env python3
"""Tests for validate-browser-finding scope + precondition fail-closed behavior."""

from __future__ import annotations

import importlib.util
import sys
from types import SimpleNamespace

from traust.paths import skill_dir

ROOT = skill_dir("validate-browser-finding") / "scripts"


def _load(name: str, filename: str):
    """Load a module by file path under a unique name (avoids clash with validate-findings)."""
    path = ROOT / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# run.py does `from adapter/scope import …` — seed those names only while loading it.
_prev_scope = sys.modules.get("scope")
_prev_adapter = sys.modules.get("adapter")

_scope = _load("vbf_scope", "scope.py")
sys.modules["scope"] = _scope
_adapter = _load("vbf_adapter", "adapter.py")
sys.modules["adapter"] = _adapter
_run = _load("vbf_run", "run.py")


# Restore so later test modules still see validate-findings' scope.
def _restore(name: str, prev):
    if prev is not None:
        sys.modules[name] = prev
    else:
        sys.modules.pop(name, None)


_restore("scope", _prev_scope)
_restore("adapter", _prev_adapter)

BrowserTarget = _scope.BrowserTarget
Scope = _scope.Scope
_origin = _scope._origin
PlanExecutor = _run.PlanExecutor


def _target(**kwargs) -> BrowserTarget:
    defaults = dict(
        victim_origin="http://victim.example.com",
        attacker_origins=["http://attacker.example.com"],
        allowed_verbs=["navigate", "screenshot", "csrf-replay"],
    )
    defaults.update(kwargs)
    return BrowserTarget(**defaults)


def test_origin_parse():
    assert _origin("http://victim.example.com/path") == "http://victim.example.com"
    assert _origin("https://victim.example.com:8443/x") == "https://victim.example.com:8443"
    assert _origin("not-a-url") is None


def test_matches_url_rejects_lookalike_domain():
    t = _target()
    assert t.matches_url("http://victim.example.com/app")
    assert not t.matches_url("http://victim.example.com.evil.net/app")
    assert t.matches_url("http://attacker.example.com/poc")


def test_allows_verb_fails_closed_when_empty():
    t = _target(allowed_verbs=[])
    assert not t.allows_verb("navigate")
    assert not t.allows_verb("csrf-replay")


def test_allows_verb_respects_list():
    t = _target()
    assert t.allows_verb("navigate")
    assert not t.allows_verb("xss-inject")


def test_check_requires_url():
    s = Scope(targets=[_target()])
    ok, reason = s.check("navigate", "")
    assert ok is False
    assert "url required" in reason


def test_check_binds_verb_to_matched_origin():
    s = Scope(targets=[_target()])
    ok, _ = s.check("navigate", "http://victim.example.com/x")
    assert ok is True
    ok, reason = s.check("xss-inject", "http://victim.example.com/x")
    assert ok is False
    assert "allowed_verbs" in reason


def test_check_rejects_unknown_origin():
    s = Scope(targets=[_target()])
    ok, reason = s.check("navigate", "http://other.example.com/")
    assert ok is False
    assert "not in any target origin" in reason


class _FakeAdapter:
    current_url = ""


def test_preconditions_fail_closed_on_unknown_id():
    adapter = _FakeAdapter()
    scope = Scope(targets=[_target()])
    audit = SimpleNamespace(record=lambda **_: None)
    ex = PlanExecutor(adapter, scope, audit)
    ex._done["step-001"] = SimpleNamespace(verdict="confirmed")
    reason = ex._check_preconditions({"preconditions": ["step-01"]})  # typo
    assert reason is not None
    assert "step-01" in reason


def test_preconditions_fail_closed_on_unconfirmed():
    adapter = _FakeAdapter()
    scope = Scope(targets=[_target()])
    audit = SimpleNamespace(record=lambda **_: None)
    ex = PlanExecutor(adapter, scope, audit)
    ex._done["step-001"] = SimpleNamespace(verdict="inconclusive")
    reason = ex._check_preconditions({"preconditions": ["step-001"]})
    assert reason is not None


def test_preconditions_pass_when_confirmed():
    adapter = _FakeAdapter()
    scope = Scope(targets=[_target()])
    audit = SimpleNamespace(record=lambda **_: None)
    ex = PlanExecutor(adapter, scope, audit)
    ex._done["step-001"] = SimpleNamespace(verdict="confirmed")
    assert ex._check_preconditions({"preconditions": ["step-001"]}) is None
