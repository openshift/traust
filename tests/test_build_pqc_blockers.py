"""Tests for the pqc-readiness blockers projection (build_pqc_blockers.py)
and the adapter-side gap fixes it ships with: HP_GOV_* facts constrained to
first-party paths, and the l2_prepass governance-count filter."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

ROOT = Path(__file__).resolve().parents[1]
PQC = skill_dir("pqc-readiness") / "scripts"
RULES = PQC.parent / "rules"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, PQC / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclass annotation resolution needs this
    spec.loader.exec_module(mod)
    return mod


bpf = _load("build_pqc_blockers")


def _readiness(remediations, who="this_app"):
    return {
        "metadata": {
            "repository": "https://github.com/acme/widget",
            "commit": "abc123def456",
            "assessed_at": "2026-08-06",
            "harness_version": "0.252.0",
            "tool": {"adapter_version": "1.4.0"},
        },
        "status": "needs_work",
        "who_sets_tls": who,
        "remediations": remediations,
    }


def _rem(n=1, category="fix-now", locations=("pkg/server/tls.go:42",), **kw):
    rem = {
        "id": f"WIDGET-abc123d-REM-{n:03d}",
        "category": category,
        "action": "Derive the metrics listener's TLS config from the "
        "platform profile — static config ignores the cluster "
        "tlsSecurityProfile.",
        "locations": list(locations),
        "remediation_effort": "moderate",
    }
    rem.update(kw)
    return rem


class TestBuildFindingsDoc:
    def test_projects_remediation_to_blockers_vocabulary(self):
        doc = bpf.build_findings_doc(_readiness([_rem()]), "widget-pqc-readiness.json")
        f = doc["findings"][0]
        assert doc["artifact"] == "pqc-blockers"
        assert f["id"] == "WIDGET-abc123d-REM-001"
        assert f["severity"] == "high"  # fix-now
        assert f["cwes"] == ["CWE-327"]
        assert f["locations"] == [{"path": "pkg/server/tls.go", "lines": "42"}]
        assert f["category"] == "cryptography"
        assert f["validation_status"] == "not_verified"
        assert f["pqc_classification"] == "pqc-blocker-config"
        assert "who_sets_tls): this_app" in f["description"]

    @pytest.mark.parametrize(
        "category,deadline,severity,pqc_class",
        [
            ("fix-now", None, "high", "pqc-blocker-config"),
            ("deadline", 2030, "medium", "clock-2030-parameter"),
            ("deadline", 2035, "low", "pqc-blocker-config"),
            ("upgrade", None, "low", "pqc-adoption"),
            ("waiting-on-upstream", None, "informational", "pqc-blocker-config"),
        ],
    )
    def test_severity_and_classification_map(self, category, deadline, severity, pqc_class):
        rem = _rem(category=category)
        if deadline:
            rem["deadline"] = deadline
        doc = bpf.build_findings_doc(_readiness([rem]), "s.json")
        f = doc["findings"][0]
        assert (f["severity"], f["pqc_classification"]) == (severity, pqc_class)

    def test_locationless_remediations_excluded_not_silent(self):
        rems = [_rem(1), _rem(2, category="waiting-on-upstream", locations=())]
        doc = bpf.build_findings_doc(_readiness(rems), "s.json")
        assert len(doc["findings"]) == 1
        assert doc["metadata"]["additional"]["excluded_remediations"] == ["WIDGET-abc123d-REM-002"]

    def test_no_eligible_remediations_returns_none(self):
        assert bpf.build_findings_doc(_readiness([]), "s.json") is None
        only_locless = [_rem(1, locations=())]
        assert bpf.build_findings_doc(_readiness(only_locless), "s.json") is None

    def test_output_validates_against_schema(self):
        pytest.importorskip("jsonschema")
        doc = bpf.build_findings_doc(
            _readiness([_rem(1), _rem(2, category="deadline", deadline=2030)]), "s.json"
        )
        assert bpf.validate_doc(doc, "test") == 0

    def test_summary_and_roadmap_cover_all_findings(self):
        doc = bpf.build_findings_doc(_readiness([_rem(1), _rem(2, category="upgrade")]), "s.json")
        counted = [i for c in doc["findings_summary"] for i in c["finding_ids"]]
        addressed = [i for r in doc["remediation_roadmap"] for i in r["addresses"]]
        ids = [f["id"] for f in doc["findings"]]
        assert sorted(counted) == sorted(ids) == sorted(addressed)


class TestEmit:
    def test_emit_writes_alongside_input(self, tmp_path):
        pytest.importorskip("jsonschema")
        src = tmp_path / "widget-pqc-readiness.json"
        src.write_text(json.dumps(_readiness([_rem()])))
        out = bpf.emit(src, None)
        assert out == tmp_path / "widget-pqc-blockers.json"
        assert json.loads(out.read_text())["artifact"] == "pqc-blockers"

    def test_emit_skips_when_nothing_eligible(self, tmp_path):
        src = tmp_path / "widget-pqc-readiness.json"
        src.write_text(json.dumps(_readiness([])))
        assert bpf.emit(src, None) is None
        assert not (tmp_path / "widget-pqc-blockers.json").exists()


class TestGovernanceFirstPartyOnly:
    """Regression for the FIO miss: vendored openshift/api type definitions
    must not produce platform-governance facts."""

    def _facts(self, pqc_facts):
        gov_vendor = pqc_facts.Fact(
            rule_id="HP_GOV_PLATFORM_OCP_DIRECT",
            file="vendor/github.com/openshift/api/config/v1/types_apiserver.go",
            line=65,
        )
        gov_fp = pqc_facts.Fact(
            rule_id="HP_GOV_PLATFORM_OCP_DIRECT", file="pkg/config/profile.go", line=10
        )
        listener_fp = pqc_facts.Fact(
            rule_id="HP_TLS_LISTENER_GO",
            file="pkg/controller/metrics/metrics.go",
            line=225,
        )
        return [gov_vendor, gov_fp, listener_fp]

    def test_post_process_drops_vendored_gov_facts(self):
        pqc_facts = _load("pqc_facts")
        facts = self._facts(pqc_facts)
        pqc_facts._post_process(facts, pqc_facts.load_tables())
        by_rule = {(f.rule_id, f.file) for f in facts}
        assert (
            "HP_GOV_PLATFORM_OCP_DIRECT",
            "vendor/github.com/openshift/api/config/v1/types_apiserver.go",
        ) not in by_rule
        assert ("HP_GOV_PLATFORM_OCP_DIRECT", "pkg/config/profile.go") in by_rule
        # non-governance vendor facts are untouched by this filter
        assert ("HP_TLS_LISTENER_GO", "pkg/controller/metrics/metrics.go") in by_rule

    def test_l2_prepass_counts_first_party_gov_only(self):
        sys.path.insert(0, str(PQC))
        try:
            l2 = _load("l2_prepass")
        finally:
            sys.path.remove(str(PQC))
        facts = {
            "facts": [
                {"rule_id": "HP_GOV_PLATFORM_OCP_DIRECT", "path_class": "vendor"},
                {"rule_id": "HP_GOV_PLATFORM_OCP_DIRECT", "path_class": "first_party"},
            ]
        }
        _tier, hints = l2.route_repo(facts, None)
        assert hints["gov_rules"] == ["HP_GOV_PLATFORM_OCP_DIRECT"]
        vendor_only = {"facts": [facts["facts"][0]]}
        _, hints2 = l2.route_repo(vendor_only, None)
        assert hints2["gov_rules"] == []


class TestListenerRulesPresent:
    def test_listener_census_rules_in_pack(self):
        import yaml

        rules = yaml.safe_load((RULES / "hp_supplement.yml").read_text())
        ids = {r["id"] for r in rules}
        assert {
            "HP_TLS_LISTENER_GO",
            "HP_TLS_SERVER_CONFIG_GO",
            "HP_TLS_LISTENER_PY",
            "HP_TLS_LISTENER_JS",
            "HP_TLS_LISTENER_RUST",
        } <= ids

    def test_go_listener_pattern_matches_fio_shape(self):
        import re

        import yaml

        rules = {r["id"]: r for r in yaml.safe_load((RULES / "hp_supplement.yml").read_text())}
        listener = re.compile(rules["HP_TLS_LISTENER_GO"]["pattern"])
        server_cfg = re.compile(rules["HP_TLS_SERVER_CONFIG_GO"]["pattern"])
        assert listener.search("err := server.ListenAndServeTLS(certFile, keyFile)")
        assert server_cfg.search("TLSConfig: tlsConfig,")
        assert server_cfg.search("tlsConfig = libgocrypto.SecureTLSConfig(tlsConfig)")
        # client-side config must not fire the server census
        assert not server_cfg.search("TLSClientConfig: &tls.Config{},")
        assert not listener.search("resp, err := client.Get(url)")

    def test_rust_listener_pattern_covers_all_backends(self):
        import re

        import yaml

        rules = {r["id"]: r for r in yaml.safe_load((RULES / "hp_supplement.yml").read_text())}
        rust = re.compile(rules["HP_TLS_LISTENER_RUST"]["pattern"])
        # openssl crate (FIPS-preferred), native-tls, rustls, axum bind
        assert rust.search("let acceptor = SslAcceptor::mozilla_intermediate_v5(m)?;")
        assert rust.search("let acceptor = tokio_native_tls::TlsAcceptor::from(inner);")
        assert rust.search("let cfg = rustls::ServerConfig::builder()")
        assert rust.search('.bind_openssl("0.0.0.0:8443", builder)?')
        # client-side types must not fire
        assert not rust.search("let c = TlsConnector::builder().build()?;")
        assert not rust.search("let cfg = rustls::ClientConfig::builder();")
