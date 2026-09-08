"""docs/skills.md is generated; the generator must be deterministic and current."""

from __future__ import annotations

import re

from traust.cli import build_skills_reference as B
from traust.paths import skill_dirs


def test_render_is_deterministic():
    assert B.render() == B.render()


def test_every_skill_has_a_section_and_nothing_else_does():
    text = B.render()
    heads = re.findall(r"^## (.+)$", text, re.M)
    skills = sorted(d.name for d in skill_dirs())
    assert sorted(h for h in heads if h not in ("Tiers", "Pipeline overview")) == skills


def test_descriptions_come_from_frontmatter_verbatim():
    text = B.render()
    for d in skill_dirs():
        fm = B._frontmatter((d / "SKILL.md").read_text(encoding="utf-8"))
        desc = B._one_line(fm.get("description", ""))
        assert desc and desc in text, d.name


def test_phased_audit_claims_its_own_slash_commands_only():
    text = B.render()
    section = text.split("## security-audit-phased\n", 1)[1].split("\n## ", 1)[0]
    assert "`/security-audit-init`" in section
    assert "`/triage`" not in section


def test_committed_reference_is_current():
    assert B.OUT.read_text(encoding="utf-8") == B.render(), (
        "docs/skills.md is stale — run python3 -m traust.cli build skills-reference"
    )
