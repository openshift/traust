#!/usr/bin/env python3
"""Tests for harnessing/3-audit/secure-code-audit/scripts/expand_config_matrix.py — the Phase-B1 (D3)
effective-defaults expander. Each fixture family mirrors one measured
config/DSN miss shape from fn-analysis §4 / deep-fn-technique-plan §1.3:
helm values chain (trustee shape), code-side fallback branch
(config-assembled DSN shape), compose/k8s env literals, plus the scope and
coverage-gap contracts."""

import json
import subprocess
import sys
from pathlib import Path

import expand_config_matrix as ecm
import pytest

from traust.paths import skill_dir

_SECURE_CODE_AUDIT_SCRIPTS = skill_dir("secure-code-audit") / "scripts"

SCRIPT = _SECURE_CODE_AUDIT_SCRIPTS / "expand_config_matrix.py"


def _expand(repo: Path) -> dict:
    return ecm.expand(repo, max_triples=2000)


def _by_key(result: dict, key: str) -> list:
    return [t for t in result["triples"] if t["key"] == key or t["key"].endswith("." + key)]


# --------------------------------------------------------------------------
# helm values chain (the trustee-shape miss)
# --------------------------------------------------------------------------


@pytest.fixture
def helm_repo(tmp_path):
    chart = tmp_path / "deploy" / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: svc\nversion: 1.0.0\n")
    (chart / "values.yaml").write_text(
        "database:\n"
        "  host: db.svc\n"
        "  sslmode: disable\n"
        "replicas: 2\n"
        "auth:\n"
        "  anonymousAccess: true\n"
    )
    (chart / "templates" / "deploy.yaml").write_text(
        "env:\n"
        "  - name: DB_DSN\n"
        "    value: postgres://u@{{ .Values.database.host }}/app"
        "?sslmode={{ .Values.database.sslmode }}\n"
    )
    return tmp_path


def test_helm_values_default_becomes_triple(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "database.sslmode")
    assert t["effective_default"] == "disable"
    assert t["source"]["system"] == "helm"
    assert t["source"]["path"].endswith("values.yaml")
    assert t["class"] == "dsn"
    assert t["judgement_required"] is True
    assert t["weak_default"] is True


def test_helm_sink_resolves_to_template_usage(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "database.sslmode")
    assert t["sink"]["status"] == "template"
    assert t["sink"]["path"].endswith("templates/deploy.yaml")
    assert "sslmode" in t["sink"]["expr"]


def test_helm_auth_default_classified(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "auth.anonymousAccess")
    assert t["class"] == "auth"
    assert t["judgement_required"] is True


def test_irrelevant_key_not_judged(helm_repo):
    result = _expand(helm_repo)
    [t] = _by_key(result, "replicas")
    assert t["judgement_required"] is False
    assert t["class"] == "other"


def test_chart_without_values_is_coverage_gap(tmp_path):
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("name: rendered-only\n")
    result = _expand(tmp_path)
    gaps = [g for g in result["coverage_gaps"] if g["system"] == "helm"]
    assert gaps and "render time" in gaps[0]["reason"]


# --------------------------------------------------------------------------
# code-side fallback chains (the config-assembled DSN shape)
# --------------------------------------------------------------------------


def test_go_getenv_if_empty_fallback(tmp_path):
    (tmp_path / "db.go").write_text(
        "package config\n\n"
        "func dsn() string {\n"
        '\tmode := os.Getenv("DB_SSLMODE")\n'
        '\tif mode == "" {\n'
        '\t\tmode = "disable"\n'
        "\t}\n"
        "\treturn mode\n"
        "}\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DB_SSLMODE")
    assert t["effective_default"] == "disable"
    assert t["source"]["system"] == "env-chain-go"
    assert t["sink"]["status"] == "code"
    assert t["judgement_required"] is True


def test_go_viper_and_cmp_or(tmp_path):
    (tmp_path / "cfg.go").write_text(
        "package cfg\n"
        "func init() {\n"
        '\tviper.SetDefault("server.tls.enabled", false)\n'
        '\taddr := cmp.Or(os.Getenv("BIND_ADDR"), "0.0.0.0:8080")\n'
        "\t_ = addr\n"
        "}\n"
    )
    result = _expand(tmp_path)
    [tls] = _by_key(result, "server.tls.enabled")
    assert tls["effective_default"] == "false"
    assert tls["class"] == "tls"
    [bind] = _by_key(result, "BIND_ADDR")
    assert bind["effective_default"] == "0.0.0.0:8080"
    assert bind["class"] == "listener"


def test_python_environ_get_default(tmp_path):
    (tmp_path / "settings.py").write_text(
        'VERIFY_TLS = os.environ.get("VERIFY_TLS", "false")\n'
        'PAGE_SIZE = os.getenv("PAGE_SIZE", 50)\n'
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "VERIFY_TLS")
    assert t["effective_default"] == "false"
    assert t["judgement_required"] is True
    [p] = _by_key(result, "PAGE_SIZE")
    assert p["judgement_required"] is False


def test_js_process_env_fallback(tmp_path):
    (tmp_path / "server.js").write_text("const debug = process.env.DEBUG_MODE || 'true';\n")
    result = _expand(tmp_path)
    [t] = _by_key(result, "DEBUG_MODE")
    assert t["effective_default"] == "true"
    assert t["class"] == "debug"


def test_test_files_excluded(tmp_path):
    (tmp_path / "db_test.go").write_text(
        'func t() { m := os.Getenv("X_MODE")\nif m == "" { m = "disable" } }\n'
    )
    result = _expand(tmp_path)
    assert _by_key(result, "X_MODE") == []


# --------------------------------------------------------------------------
# compose + k8s env literals + kustomize
# --------------------------------------------------------------------------


def test_compose_environment(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        "      DATABASE_URL: postgres://u:p@db/app?sslmode=disable\n"
        "      LOG_LEVEL: info\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DATABASE_URL")
    assert t["class"] == "dsn"
    assert t["sink"] == {"status": "service", "service": "api"}


def test_k8s_deployment_env_and_configmap(tmp_path):
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          env:\n"
        "            - name: INSECURE_SKIP_VERIFY\n"
        '              value: "true"\n'
        "---\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: {name: cfg}\n"
        "data:\n"
        '  auth.anonymous: "enabled"\n'
    )
    result = _expand(tmp_path)
    [skip] = _by_key(result, "INSECURE_SKIP_VERIFY")
    assert skip["class"] == "tls"
    assert skip["sink"]["container"] == "app"
    [anon] = _by_key(result, "auth.anonymous")
    assert anon["source"]["system"] == "k8s-configmap"


def test_kustomize_literals(tmp_path):
    (tmp_path / "kustomization.yaml").write_text(
        "configMapGenerator:\n  - name: cfg\n    literals:\n      - DB_SSLMODE=prefer\n"
    )
    result = _expand(tmp_path)
    [t] = _by_key(result, "DB_SSLMODE")
    assert t["effective_default"] == "prefer"
    assert t["weak_default"] is True


# --------------------------------------------------------------------------
# scope + coverage-gap + output contracts
# --------------------------------------------------------------------------


def test_no_override_cross_product(tmp_path):
    """Plan D3 risk (c): one triple per (key, default, source), never the
    override combination space — two values files yield two triples for
    the same key, not a matrix of joint states."""
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: svc\n")
    (chart / "values.yaml").write_text("tlsVerify: false\n")
    (chart / "values-prod.yaml").write_text("tlsVerify: true\n")
    result = _expand(tmp_path)
    assert len(_by_key(result, "tlsVerify")) == 2


def test_toml_ini_emit_coverage_gap(tmp_path):
    (tmp_path / "app.toml").write_text("[db]\nsslmode = 'disable'\n")
    (tmp_path / "legacy.ini").write_text("[auth]\nanonymous = yes\n")
    result = _expand(tmp_path)
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "config-file"]
    assert gap["count"] == 2
    assert not _by_key(result, "db.sslmode")


def test_vendor_and_dotgit_skipped(tmp_path):
    v = tmp_path / "vendor" / "lib"
    v.mkdir(parents=True)
    (v / "compose.yaml").write_text(
        "services:\n  x:\n    environment:\n      SECRET_KEY: hunter2\n"
    )
    result = _expand(tmp_path)
    assert result["triples"] == []


def test_triple_cap_records_gap_and_keeps_judged_first(tmp_path):
    lines = "\n".join(f'K{i} = os.environ.get("PLAIN_{i}", "v")' for i in range(30))
    (tmp_path / "big.py").write_text(lines + '\nS = os.environ.get("DB_PASSWORD", "changeme")\n')
    result = ecm.expand(tmp_path, max_triples=5)
    assert result["stats"]["total"] == 5
    assert result["triples"][0]["key"] == "DB_PASSWORD"  # judged kept first
    [gap] = [g for g in result["coverage_gaps"] if g["system"] == "expander"]
    assert gap["count"] == 26


def test_stats_and_dedupe(helm_repo):
    result = _expand(helm_repo)
    s = result["stats"]
    assert s["total"] == len(result["triples"])
    assert s["judgement_required"] >= 3
    sigs = {
        (t["key"], t["effective_default"], t["source"]["path"], t["source"]["line"])
        for t in result["triples"]
    }
    assert len(sigs) == s["total"]


def test_cli_writes_artifact(tmp_path, helm_repo):
    out = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(helm_repo), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["artifact"] == "config-matrix"
    assert data["stats"]["total"] > 0
    assert "to judge" in proc.stdout
