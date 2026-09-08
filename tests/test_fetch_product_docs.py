#!/usr/bin/env python3
"""Tests for traust.ops.fetch_product_docs — offline (network _get is
stubbed); the deterministic structuring is what's under test."""

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
from traust.ops import fetch_product_docs as fpd

HTML = """<html><head><script>junk()</script><style>x{}</style></head>
<body><nav>menu</nav>
<h1 id="top">Managing clusters</h1><p>Intro &amp; text.</p>
<h2 id="sec-2fa">Two-factor authentication</h2>
<p>For greater security, use 2FA.</p>
<h2>Untitled anchorless</h2><p>tail</p>
<footer>foot</footer></body></html>"""


def test_strip_preserves_section_anchors():
    txt = fpd.strip_to_text(HTML, "https://docs.redhat.com/x/index")
    assert "## Managing clusters [https://docs.redhat.com/x/index#top]" in txt
    assert "## Two-factor authentication [https://docs.redhat.com/x/index#sec-2fa]" in txt
    assert "For greater security, use 2FA." in txt
    assert "junk()" not in txt and "menu" not in txt


def test_fetch_writes_manifest_and_caches(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(fpd, "_get", lambda url: (calls.append(url), HTML)[1])
    m = fpd.fetch("p", "1", ["guide_a"], tmp_path, refresh=False)
    assert m["guides"][0]["state"] == "fetched"
    assert "CC-BY-SA" in m["license_note"]
    m2 = fpd.fetch("p", "1", ["guide_a"], tmp_path, refresh=False)
    assert m2["guides"][0]["state"] == "cached"
    assert len(calls) == 1
    assert json.loads((tmp_path / "manifest.json").read_text())["artifact"] == "product-docs-fetch"


def test_fetch_failure_is_loud_never_partial(tmp_path, monkeypatch):
    def boom(url):
        raise RuntimeError("403")

    monkeypatch.setattr(fpd, "_get", boom)
    with pytest.raises(SystemExit, match="refusing a partial-silent"):
        fpd.fetch("p", "1", ["g"], tmp_path, refresh=False)


def test_list_guides_fails_loud_on_empty(monkeypatch):
    monkeypatch.setattr(fpd, "_get", lambda url: "<html>nothing</html>")
    with pytest.raises(SystemExit, match="no guides found"):
        fpd.list_guides("p", "1")
