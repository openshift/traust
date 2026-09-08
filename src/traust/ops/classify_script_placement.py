#!/usr/bin/env python3
"""Classify top-level scripts for C8 placement decisions.

For each scripts/*.py file, compute:
- non-test python importers (from scripts/, harnessing/, tests/)
- SKILL.md references under harnessing/

Outputs a per-file table and class summary:
- shared-library: imported by >=3 non-test callers
- multi-skill-cli: referenced by >=2 SKILL.md files
- single-skill-cli: referenced by exactly 1 SKILL.md and 0 non-test importers
- orphan: no non-test importers and no SKILL.md refs
"""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
from pathlib import Path

from traust.paths import CLI_DIR, HARNESSING_DIR


def _script_modules() -> dict[str, Path]:
    modules: dict[str, Path] = {}
    if CLI_DIR.is_dir():
        for p in CLI_DIR.glob("*.py"):
            if p.is_file() and p.stem != "__init__":
                modules[p.stem] = p
    return modules


def _python_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return [p for p in root.rglob("*.py") if p.is_file() and "clones" not in p.parts]


def _is_test_file(path: Path) -> bool:
    return "tests" in path.parts or path.name.startswith("test_")


def _imports_script_modules(file_path: Path, modules: set[str]) -> set[str]:
    hits: set[str] = set()
    try:
        tree = ast.parse(file_path.read_text(), filename=str(file_path))
    except Exception:
        return hits
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in modules:
                    hits.add(root)
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            root = node.module.split(".")[0]
            if root in modules:
                hits.add(root)
    return hits


def _skill_refs(modules: set[str]) -> dict[str, set[Path]]:
    refs: dict[str, set[Path]] = defaultdict(set)
    for skill in HARNESSING_DIR.rglob("SKILL.md"):
        try:
            text = skill.read_text()
        except Exception:
            continue
        for m in modules:
            if f"{m}.py" in text:
                refs[m].add(skill)
    return refs


def classify() -> tuple[list[dict[str, object]], dict[str, int]]:
    scripts = _script_modules()
    modules = set(scripts)
    importers: dict[str, set[Path]] = defaultdict(set)
    importers_non_test: dict[str, set[Path]] = defaultdict(set)

    scan_roots = [CLI_DIR, HARNESSING_DIR, HARNESSING_DIR.parent / "tests"]
    for root in scan_roots:
        for py in _python_files(root):
            self_name = py.stem if py.parent == CLI_DIR else None
            hits = _imports_script_modules(py, modules)
            for m in hits:
                if self_name and m == self_name:
                    continue
                importers[m].add(py)
                if not _is_test_file(py):
                    importers_non_test[m].add(py)

    skill_refs = _skill_refs(modules)

    rows: list[dict[str, object]] = []
    counts = {
        "shared-library": 0,
        "multi-skill-cli": 0,
        "single-skill-cli": 0,
        "orphan": 0,
        "other": 0,
    }

    for name in sorted(modules):
        non_test = len(importers_non_test.get(name, set()))
        total_importers = len(importers.get(name, set()))
        skill_count = len(skill_refs.get(name, set()))
        if non_test >= 3:
            cls = "shared-library"
        elif skill_count >= 2:
            cls = "multi-skill-cli"
        elif skill_count == 1 and non_test == 0:
            cls = "single-skill-cli"
        elif skill_count == 0 and non_test == 0:
            cls = "orphan"
        else:
            cls = "other"
        counts[cls] += 1
        rows.append(
            {
                "module": name,
                "class": cls,
                "non_test_importers": non_test,
                "total_importers": total_importers,
                "skill_refs": skill_count,
                "path": str(scripts[name]),
            }
        )
    return rows, counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--only",
        choices=["shared-library", "multi-skill-cli", "single-skill-cli", "orphan", "other"],
    )
    args = ap.parse_args()

    rows, counts = classify()
    print("class,count")
    for k in ["shared-library", "multi-skill-cli", "single-skill-cli", "orphan", "other"]:
        print(f"{k},{counts[k]}")
    print("")
    print("module,class,non_test_importers,total_importers,skill_refs,path")
    for row in rows:
        if args.only and row["class"] != args.only:
            continue
        print(
            f"{row['module']},{row['class']},{row['non_test_importers']},"
            f"{row['total_importers']},{row['skill_refs']},{row['path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
