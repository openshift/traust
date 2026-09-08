"""Tests for collect_cloud_inventory.py + the inventory scope adapter."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ci = _load(
    "collect_cloud_inventory",
    skill_dir("compliance-check") / "scripts" / "collect_cloud_inventory.py",
)
scope_mod = _load("vf_scope_inv_test", skill_dir("validate-findings") / "scope.py")
Scope, Action = scope_mod.Scope, scope_mod.Action


def _targets(tmp_path, profiles=("stage",), contexts=()):
    f = tmp_path / "targets.yaml"
    f.write_text(
        "engagement: t\nauthorized_by: t\n"
        "cloud_inventory:\n"
        f"  aws_profiles: {list(profiles)}\n"
        f"  cluster_contexts: {list(contexts)}\n"
    )
    return f


# ---------------- scope adapter ----------------


def test_inventory_scope_explicit_only():
    s = Scope()
    s.modes.add("inline")
    s.inventory_aws_profiles.add("stage")
    ok, reason = s.is_in_scope(
        Action(adapter="inventory", verb="enumerate", resource="aws_profile", name="stage")
    )
    assert not ok and "mode-1" in reason


def test_inventory_scope_profile_and_verb_gate(tmp_path):
    s = Scope.from_targets_file(_targets(tmp_path, ("stage",), ("lab",)))
    ok, _ = s.is_in_scope(
        Action(adapter="inventory", verb="enumerate", resource="aws_profile", name="stage")
    )
    assert ok
    ok, r = s.is_in_scope(
        Action(adapter="inventory", verb="enumerate", resource="aws_profile", name="prod")
    )
    assert not ok and "prod" in r
    ok, r = s.is_in_scope(
        Action(adapter="inventory", verb="delete", resource="aws_profile", name="stage")
    )
    assert not ok and "read-only" in r
    ok, _ = s.is_in_scope(
        Action(adapter="inventory", verb="enumerate", resource="cluster_context", name="lab")
    )
    assert ok


# ---------------- collection with mocked aws ----------------

AWS_RESPONSES = {
    ("s3api", "list-buckets"): {"Buckets": [{"Name": "data-prod"}]},
    ("s3api", "get-bucket-location"): {"LocationConstraint": "eu-west-1"},
    ("s3api", "get-bucket-encryption"): {"ServerSideEncryptionConfiguration": {"Rules": []}},
    ("s3api", "get-public-access-block"): {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    },
    ("rds", "describe-db-instances"): {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "db1",
                "AvailabilityZone": "eu-west-1a",
                "StorageEncrypted": True,
                "PubliclyAccessible": False,
            }
        ]
    },
}


def _mock_aws(profile, *args):
    return AWS_RESPONSES.get(tuple(args[:2])), None


def test_collect_aws_profile_shapes(monkeypatch):
    monkeypatch.setattr(ci, "_aws", _mock_aws)
    resources, gaps = ci.collect_aws_profile("stage")
    assert gaps == []
    by_kind = {r["kind"]: r for r in resources}
    s3 = by_kind["s3_bucket"]
    assert s3["region"] == "eu-west-1"
    assert s3["encryption_at_rest"] is True
    assert s3["public_exposure"] is False
    rds = by_kind["rds_instance"]
    assert rds["region"] == "eu-west-1"
    assert rds["encryption_at_rest"] is True


def test_missing_encryption_config_is_false_not_gap(monkeypatch):
    def mock(profile, *args):
        if args[:2] == ("s3api", "get-bucket-encryption"):
            return None, "ServerSideEncryptionConfigurationNotFoundError"
        return _mock_aws(profile, *args)

    monkeypatch.setattr(ci, "_aws", mock)
    resources, gaps = ci.collect_aws_profile("stage")
    s3 = next(r for r in resources if r["kind"] == "s3_bucket")
    assert s3["encryption_at_rest"] is False
    assert not any("encryption" in g for g in gaps)


def test_main_snapshot_deterministic_and_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "_aws", _mock_aws)
    targets = _targets(tmp_path)
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    assert ci.main(["--targets", str(targets), "--out", str(out1), "--skip-clusters"]) == 0
    assert ci.main(["--targets", str(targets), "--out", str(out2), "--skip-clusters"]) == 0
    d1, d2 = (json.loads(p.read_text()) for p in (out1, out2))
    assert d1["metadata"]["snapshot_id"] == d2["metadata"]["snapshot_id"]
    assert d1["resources"] == d2["resources"]
    audit = (tmp_path / "cloud-inventory-audit.jsonl").read_text()
    assert '"scope_allowed": true' in audit


def test_main_out_of_scope_profile_is_gap_not_call(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(ci, "collect_aws_profile", lambda p: called.append(p) or ([], []))
    targets = tmp_path / "t.yaml"
    # profile listed under an UNRELATED key — not unlocked
    targets.write_text(
        "engagement: t\ncloud_inventory:\n  aws_profiles: []\n  cluster_contexts: []\n"
    )
    out = tmp_path / "o.json"
    assert ci.main(["--targets", str(targets), "--out", str(out)]) == 0
    assert called == []
    doc = json.loads(out.read_text())
    assert doc["resources"] == []
