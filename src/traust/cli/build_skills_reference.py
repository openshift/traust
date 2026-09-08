#!/usr/bin/env python3
"""Generate docs/skills.md from the skill tree — never hand-edit that file.

Every skill already carries its summary in SKILL.md frontmatter
(`description`), its tier in `metadata.harness.tier`, its stage in its
directory, and its wiring in an `## Integrations` section. The reference
page is a projection of those facts, so it is generated from them: one
`## <skill>` section per skill (the docs gate requires that shape), the
frontmatter description verbatim, tier, stage, slash command(s), and a link
to the SKILL.md. Prose written here by hand drifts from the skill; prose
generated here cannot.

    python3 -m traust.cli.build_skills_reference           # write docs/skills.md
    python3 -m traust.cli.build_skills_reference --check   # exit 1 if it is stale
    python3 -m traust.cli.build_skills_reference --stdout  # print, write nothing

The docs-consistency gate runs `--check`; alignment rule A13 asks for a
regeneration whenever a SKILL.md changes.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

from traust.paths import HARNESS_ROOT, skill_dirs

OUT = HARNESS_ROOT / "docs" / "skills.md"
COMMANDS_DIR = HARNESS_ROOT / ".claude" / "commands"

STAGE_LABELS = {
    "1-inventory": "① Inventory",
    "2-threat-model": "② Threat model",
    "3-audit": "③ Audit",
    "4-triage": "④ Triage",
    "5-validate": "⑤ Validation",
    "6-fuzz": "⑥ Fuzzing",
    "7-remediate": "⑦ Remediation",
    "8-verify": "⑧ Verification",
    "9-deliver": "⑨ Delivery",
}

TIERS_TEXT = """## Tiers

Every `SKILL.md` declares `metadata.harness.tier` — what kind of thing the
skill is, and therefore how much investment it earns. Tier is orthogonal to
pipeline stage: it says whether a skill should exist, not where it runs.
`metadata` is the Agent Skills spec's sanctioned extension point, so harness
taxonomy rides there under a `harness.` prefix. Alignment rule U3 requires the
field on every skill.

| Tier | Means | Investment |
|------|-------|------------|
| `primary` | Does work only an LLM can do — find, verify, prove, fix. | Refactor and improve. |
| `secondary` | Compensates for a system the deployment does not have (ownership API, tracker client, BI layer, system of record). | Replace with a deterministic integration rather than polish. Adding one means naming the gap it stands in for. |
| `tertiary` | An org-specific island, or not an LLM's job at all. | Quarantine or drop. |
| `ci` | The harness's own gates — neither scan-and-fix value nor compensation. | Keep, keep out of the user-facing index. |
"""


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    try:
        data = yaml.safe_load(text[3:end])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _stage(skill_dir: Path) -> tuple[str, str]:
    """(sort key, label). Stage skills sort by stage number; root skills after."""
    parent = skill_dir.parent.name
    if parent in STAGE_LABELS:
        return (parent, STAGE_LABELS[parent])
    return ("z", "—")


def _commands(name: str, skill_text: str, all_skill_names: set[str]) -> list[str]:
    """Slash commands that invoke this skill: the same-named wrapper, plus any
    wrapper the SKILL.md names as one of its own commands (`/<stem>`) where
    that stem is not itself another skill (so a skill that merely mentions
    `/triage` does not claim triage's command)."""
    stems = {p.stem for p in COMMANDS_DIR.glob("*.md")}
    found: list[str] = []
    if name in stems:
        found.append(f"/{name}")
    for stem in sorted(set(re.findall(r"(?<![\w/])/([a-z0-9][a-z0-9-]+)\b", skill_text))):
        if (
            stem in stems
            and stem != name
            and stem not in all_skill_names
            and f"/{stem}" not in found
        ):
            found.append(f"/{stem}")
    return found


def _has_integrations(text: str) -> bool:
    return re.search(r"^## Integrations", text, re.M) is not None


def _one_line(desc: str) -> str:
    return " ".join(str(desc).split())


def render(repo: Path = HARNESS_ROOT) -> str:
    entries = []
    all_names = {d.name for d in skill_dirs(repo)}
    for d in skill_dirs(repo):
        text = (d / "SKILL.md").read_text(encoding="utf-8")
        fm = _frontmatter(text)
        meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
        key, label = _stage(d)
        entries.append(
            {
                "name": d.name,
                "rel": d.relative_to(repo).as_posix(),
                "description": _one_line(
                    fm.get("description") or "(no description in frontmatter)"
                ),
                "tier": str(meta.get("harness.tier") or "—").strip('"'),
                "stage_key": key,
                "stage": label,
                "commands": _commands(d.name, text, all_names),
                "integrations": _has_integrations(text),
                "argument_hint": fm.get("argument-hint"),
            }
        )

    ordered = sorted(entries, key=lambda e: (e["stage_key"], e["name"]))

    out: list[str] = []
    out.append("# Skills Reference\n")
    out.append(
        "<!-- GENERATED by python3 -m traust.cli.build_skills_reference — do not edit; "
        "edit the skill's SKILL.md frontmatter and regenerate. -->\n"
    )
    out.append(
        "Every skill is a self-contained directory under `harnessing/` holding a `SKILL.md`\n"
        "prompt and optional scripts; `.claude/skills/` and `.crush/skills/` are symlink\n"
        "trees for agent discovery. This page is generated from those files: the\n"
        "description is each skill's own frontmatter, verbatim. For how a skill works,\n"
        "read its `SKILL.md`; for what it produces and consumes, its `## Integrations`\n"
        "section; for the artifact chain across skills, [artifacts.md](artifacts.md).\n"
    )
    out.append(TIERS_TEXT)
    out.append("## Pipeline overview\n")
    out.append("| Skill | Stage | Tier | Slash command |")
    out.append("|-------|-------|------|---------------|")
    for e in ordered:
        cmds = ", ".join(f"`{c}`" for c in e["commands"]) or "—"
        out.append(f"| [{e['name']}](#{e['name']}) | {e['stage']} | `{e['tier']}` | {cmds} |")
    out.append("")
    for e in ordered:
        out.append(f"## {e['name']}\n")
        out.append(e["description"] + "\n")
        meta_lines = [
            f"- **Stage:** {e['stage']}",
            f"- **Tier:** `{e['tier']}`",
            f"- **Invoke:** {', '.join(f'`{c}`' for c in e['commands']) or 'by name in the agent (no slash command)'}"
            + (f" — arguments: `{e['argument_hint']}`" if e["argument_hint"] else ""),
            f"- **Skill:** [{e['rel']}/SKILL.md]({'../' + e['rel']}/SKILL.md)",
        ]
        if e["integrations"]:
            meta_lines.append(
                f"- **Produces / consumes:** [Integrations]({'../' + e['rel']}/SKILL.md#integrations)"
            )
        out.extend(meta_lines)
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if docs/skills.md differs from the generated text",
    )
    ap.add_argument(
        "--stdout", action="store_true", help="print the generated text instead of writing"
    )
    args = ap.parse_args(argv)
    text = render()
    if args.stdout:
        sys.stdout.write(text)
        return 0
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(
                f"docs/skills.md is stale — regenerate with: python3 -m {__name__}", file=sys.stderr
            )
            return 1
        print("docs/skills.md is current")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(HARNESS_ROOT)} ({text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["build", "skills-reference", *sys.argv[1:]]))
