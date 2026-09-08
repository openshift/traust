#!/usr/bin/env python3
"""Tests for traust.cli.emit_doc_variance — the only write path into
doc-variance registers (schema-gated, official-docs-only enforced)."""

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
from traust.cli import emit_doc_variance as edv


def _rec(
    rid="dv-tls-001",
    url="https://docs.redhat.com/en/documentation/"
    "openshift_container_platform/4.22/html-single/"
    "security_and_compliance/index#tls-security-profiles",
):
    return {
        "id": rid,
        "source": {
            "product_slug": "openshift_container_platform",
            "version": "4.22",
            "url": url,
            "quote": "You can use TLS security profiles...",
        },
        "claim": "the platform enforces the configured TLS profile",
        "code_evidence": [
            {
                "repo": "openshift/api",
                "ref": "release-4.22",
                "path": "config/v1/types_tlssecurityprofile.go",
            }
        ],
        "variance": "overclaim",
        "verified_at": "2026-07-30T23:00:00+00:00",
        "disposition": "open",
    }


def test_new_register_created_and_valid(tmp_path):
    reg = tmp_path / "x-doc-variance.json"
    stats = edv.emit(reg, [_rec()], "https://github.com/openshift/api", update=False)
    assert stats == {"added": 1, "unchanged": 0, "updated": 0, "total": 1}
    doc = json.loads(reg.read_text())
    assert doc["metadata"]["repository"] == "https://github.com/openshift/api"


def test_idempotent_reemit_is_noop(tmp_path):
    reg = tmp_path / "x-doc-variance.json"
    edv.emit(reg, [_rec()], "https://r", update=False)
    stats = edv.emit(reg, [_rec()], None, update=False)
    assert stats["unchanged"] == 1 and stats["total"] == 1


def test_changed_record_refused_without_update(tmp_path):
    reg = tmp_path / "x-doc-variance.json"
    edv.emit(reg, [_rec()], "https://r", update=False)
    changed = _rec()
    changed["disposition"] = "doc_corrected"
    with pytest.raises(SystemExit, match="silent rewrite refused"):
        edv.emit(reg, [changed], None, update=False)


def test_update_supersedes_never_rewrites(tmp_path):
    reg = tmp_path / "x-doc-variance.json"
    edv.emit(reg, [_rec()], "https://r", update=False)
    changed = _rec()
    changed["disposition"] = "doc_corrected"
    stats = edv.emit(reg, [changed], None, update=True)
    doc = json.loads(reg.read_text())
    assert stats["updated"] == 1 and stats["total"] == 2
    assert doc["records"][0]["disposition"] == "superseded"
    assert doc["records"][1]["disposition"] == "doc_corrected"


def test_unofficial_source_refused_by_schema(tmp_path):
    reg = tmp_path / "x-doc-variance.json"
    bad = _rec(url="https://docs.google.com/document/d/whatever")
    with pytest.raises(SystemExit, match="refused"):
        edv.emit(reg, [bad], "https://r", update=False)
    assert not reg.exists()
