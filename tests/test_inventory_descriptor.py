"""traust.inventory — the inventory descriptor (<inputs>/inventory.yaml).

Segment layout is declared by kind, never inferred from the directory name.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from traust.inventory import (
    DEFAULT_KIND,
    InventoryDescriptorError,
    load_descriptor,
)


def _inputs(text: str | None) -> Path:
    td = Path(tempfile.mkdtemp())
    if text is not None:
        (td / "inventory.yaml").write_text(text)
    return td


def test_missing_descriptor_means_every_segment_is_groups():
    d = load_descriptor(_inputs(None))
    assert d.path is None
    assert d.kind("openshift") == DEFAULT_KIND
    assert d.kind("anything") == "groups"
    assert d.label("my-seg") == "My-Seg"
    assert d.order == []
    assert d.first_of_kind("services") is None
    assert d.priority(["b", "a"]) == ["a", "b"]


def test_none_inputs_is_the_empty_descriptor():
    assert load_descriptor(None).kind("x") == "groups"


def test_declared_kinds_labels_and_priority_order():
    d = load_descriptor(
        _inputs(
            "segments:\n"
            "  platform: {kind: release-payload, label: Platform, "
            "release_label: 'PLT {version}'}\n"
            "  catalog: {kind: catalog}\n"
            "  svc: {kind: services, label: Services}\n"
            "  extra:\n"
        )
    )
    assert d.kind("platform") == "release-payload"
    assert d.kind("catalog") == "catalog"
    assert d.kind("svc") == "services"
    assert d.kind("extra") == "groups"  # declared, kind defaulted
    assert d.kind("undeclared") == "groups"
    assert d.label("platform") == "Platform"
    assert d.label("catalog") == "Catalog"  # title-cased fallback
    assert d.segment("platform").release_label("4.19") == "PLT 4.19"
    assert d.segment("svc").release_label("1") == "Services 1"
    assert d.order == ["platform", "catalog", "svc", "extra"]
    assert d.first_of_kind("services") == "svc"
    # declared first in declaration order, then the rest by name
    assert d.priority(["zzz", "svc", "aaa", "platform"]) == ["platform", "svc", "aaa", "zzz"]


def test_kind_string_shorthand():
    d = load_descriptor(_inputs("segments:\n  svc: services\n"))
    assert d.kind("svc") == "services"


@pytest.mark.parametrize(
    "text",
    [
        "segments:\n  x: {kind: bogus}\n",
        "segments: [a, b]\n",
        "- not a mapping\n",
        "segments:\n  x: 42\n",
    ],
)
def test_malformed_descriptor_is_an_error_not_a_silent_default(text):
    with pytest.raises(InventoryDescriptorError):
        load_descriptor(_inputs(text))
