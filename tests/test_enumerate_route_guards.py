#!/usr/bin/env python3
"""Tests for harnessing/3-audit/secure-code-audit/scripts/enumerate_route_guards.py — the Phase-B2 (D2)
route×guard matrix enumerator. The asymmetry fixtures mirror the AWX
miss shape: sibling registrations in one file where some carry the
guard and some don't (awx-false-negative-analysis, deep-fn plan §1.3)."""

import json
import subprocess
import sys
from pathlib import Path

import enumerate_route_guards as erg
import pytest

from traust.paths import skill_dir

_SECURE_CODE_AUDIT_SCRIPTS = skill_dir("secure-code-audit") / "scripts"

SCRIPT = _SECURE_CODE_AUDIT_SCRIPTS / "enumerate_route_guards.py"


def _enum(repo: Path) -> dict:
    return erg.enumerate_routes(repo)


def _by_pattern(result: dict, pattern: str) -> list:
    return [r for r in result["routes"] if r["pattern"] == pattern]


# --------------------------------------------------------------------------
# go-http
# --------------------------------------------------------------------------


@pytest.fixture
def go_asym_repo(tmp_path):
    (tmp_path / "server.go").write_text(
        "package api\n\n"
        "func routes(mux *http.ServeMux) {\n"
        '\tmux.HandleFunc("/api/jobs", requireAuth(handleJobs))\n'
        '\tmux.HandleFunc("/api/admin", requireAuth(handleAdmin))\n'
        '\tmux.HandleFunc("/api/callback", handleCallback)\n'
        "}\n"
    )
    return tmp_path


def test_go_guarded_and_bare_rows(go_asym_repo):
    result = _enum(go_asym_repo)
    [jobs] = _by_pattern(result, "/api/jobs")
    assert jobs["guards"] == ["requireAuth"]
    assert jobs["judgement_required"] is False
    [cb] = _by_pattern(result, "/api/callback")
    assert cb["guards"] == []
    assert cb["judgement_required"] is True


def test_go_asymmetry_group_detected(go_asym_repo):
    result = _enum(go_asym_repo)
    [asym] = result["asymmetries"]
    assert asym["unguarded"] == ["/api/callback"]
    assert set(asym["guarded"]) == {"/api/jobs", "/api/admin"}
    [cb] = _by_pattern(result, "/api/callback")
    assert cb["asymmetry"] is True


def test_go_receiver_scoped_use_middleware(tmp_path):
    (tmp_path / "router.go").write_text(
        "package api\n"
        "func routes(r chi.Router) {\n"
        "\tr.Use(authMiddleware)\n"
        '\tr.Get("/things", listThings)\n'
        "}\n"
    )
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "/things")
    assert row["scope_guards"] == ["authMiddleware"]
    assert row["guards"] == []
    assert row["judgement_required"] is False


def test_go_unguard_marker_forces_judgement(tmp_path):
    (tmp_path / "public.go").write_text(
        "package api\n"
        "func routes(r chi.Router) {\n"
        '\tr.Get("/metrics", skipAuth(metricsHandler))\n'
        "}\n"
    )
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "/metrics")
    assert row["judgement_required"] is True
    assert row["unguard_markers"] == ["skipAuth"]


def test_go_test_files_excluded(tmp_path):
    (tmp_path / "server_test.go").write_text(
        'func t(mux *http.ServeMux) { mux.HandleFunc("/t", handler) }\n'
    )
    assert _enum(tmp_path)["routes"] == []


# --------------------------------------------------------------------------
# django-drf
# --------------------------------------------------------------------------


@pytest.fixture
def django_repo(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "urls.py").write_text(
        "urlpatterns = [\n"
        "    path('jobs/', JobView.as_view()),\n"
        "    path('callback/', CallbackView.as_view()),\n"
        "    path('legacy/', legacy_view),\n"
        "]\n"
    )
    (app / "views.py").write_text(
        "class JobView(APIView):\n"
        "    permission_classes = [IsAuthenticated]\n"
        "    def get(self, request): ...\n"
        "\n"
        "class CallbackView(APIView):\n"
        "    permission_classes = [AllowAny]\n"
        "    def post(self, request): ...\n"
        "\n"
        "@login_required\n"
        "def legacy_view(request): ...\n"
    )
    return tmp_path


def test_django_permission_classes_resolved(django_repo):
    result = _enum(django_repo)
    [jobs] = _by_pattern(result, "jobs/")
    assert jobs["guards"] == ["IsAuthenticated"]
    assert jobs["judgement_required"] is False
    assert jobs["handler"]["path"].endswith("views.py")


def test_django_allowany_is_judged(django_repo):
    result = _enum(django_repo)
    [cb] = _by_pattern(result, "callback/")
    assert "AllowAny" in cb["unguard_markers"]
    assert cb["judgement_required"] is True


def test_django_decorator_guard(django_repo):
    result = _enum(django_repo)
    [legacy] = _by_pattern(result, "legacy/")
    assert legacy["guards"] == ["login_required"]


def test_drf_default_permissions_as_scope_guard(tmp_path):
    app = tmp_path / "svc"
    app.mkdir()
    (app / "settings.py").write_text(
        "REST_FRAMEWORK = {\n"
        "    'DEFAULT_PERMISSION_CLASSES': ["
        "'rest_framework.permissions.IsAuthenticated'],\n"
        "}\n"
    )
    (app / "urls.py").write_text("urlpatterns = [path('items/', ItemView.as_view())]\n")
    (app / "views.py").write_text("class ItemView(APIView):\n    def get(self, request): ...\n")
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "items/")
    assert row["guards"] == []
    assert any("IsAuthenticated" in g for g in row["scope_guards"])
    assert row["judgement_required"] is False


def test_django_no_guard_no_default_is_judged(tmp_path):
    app = tmp_path / "svc"
    app.mkdir()
    (app / "urls.py").write_text("urlpatterns = [path('open/', OpenView.as_view())]\n")
    (app / "views.py").write_text("class OpenView(APIView):\n    def get(self, request): ...\n")
    result = _enum(tmp_path)
    [row] = _by_pattern(result, "open/")
    assert row["judgement_required"] is True


# --------------------------------------------------------------------------
# coverage gaps + output contracts
# --------------------------------------------------------------------------


def test_express_detected_as_coverage_gap(tmp_path):
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/things', handler);\n"
    )
    result = _enum(tmp_path)
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "express"]
    assert "UNENUMERATED" in gap["reason"]
    assert result["routes"] == []


def test_stats_and_ordering(go_asym_repo):
    result = _enum(go_asym_repo)
    s = result["stats"]
    assert s["total"] == 3
    assert s["judgement_required"] == 1
    assert s["asymmetry_rows"] == 1
    # judged/asymmetry rows sort first
    assert result["routes"][0]["pattern"] == "/api/callback"


def test_cli_writes_artifact(tmp_path, go_asym_repo):
    out = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(go_asym_repo), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["artifact"] == "route-guard-matrix"
    assert data["stats"]["total"] == 3
    assert "asymmetry groups" in proc.stdout
