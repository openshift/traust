#!/usr/bin/env python3
"""attack_refs.py — single source of truth for ATT&CK technique references.

Loads the pinned, vendored technique table (tables/attack-techniques.json,
built by build_attack_table.py from one sha256-pinned ATT&CK release) and
the harness-vocabulary mapping (tables/attack-mapping.json). Every harness
component that touches a technique ID goes through this module:

  * validate-findings/chain.py   — capability_map (chain annotation)
  * threat-model attack_refs     — ID validation for the optional column
  * build_attack_coverage.py     — category_map + Navigator layer

Determinism contract: technique IDs are only ever SELECTED from these
tables, never free-authored; validate_ids() rejects unknown, revoked, and
deprecated IDs so a stale reference fails loudly at write time.

CLI:
  python3 attack_refs.py --validate T1611 T1552.007   # exit 1 on any bad ID
  python3 attack_refs.py --validate-tables            # mapping vs pinned table
"""

import json
import re
import sys
from pathlib import Path

TABLES = Path(__file__).resolve().parents[1] / "tables"
_ID_RX = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_techniques():
    t = json.loads((TABLES / "attack-techniques.json").read_text(encoding="utf-8"))
    return t


def load_mapping():
    return json.loads((TABLES / "attack-mapping.json").read_text(encoding="utf-8"))


def _map_pairs(section: dict):
    return [(k, v) for k, v in section.items() if not k.startswith("_") and isinstance(v, list)]


def capability_map() -> dict:
    """capability -> [technique IDs] (validate-findings chain annotation)."""
    return dict(_map_pairs(load_mapping()["capability_map"]))


def category_map() -> dict:
    """finding category -> [candidate technique IDs]."""
    return dict(_map_pairs(load_mapping()["category_map"]))


def validate_ids(ids, techniques=None) -> list[str]:
    """Return a list of error strings ('' clean). Rejects malformed,
    unknown, revoked, and deprecated technique IDs."""
    tt = (techniques or load_techniques())["techniques"]
    errs = []
    for i in ids:
        if not isinstance(i, str) or not _ID_RX.match(i):
            errs.append(f"{i}: malformed technique ID")
            continue
        e = tt.get(i)
        if e is None:
            errs.append(f"{i}: not in pinned ATT&CK table")
        elif e.get("revoked"):
            errs.append(
                f"{i}: revoked" + (f" -> use {e['revoked_by']}" if e.get("revoked_by") else "")
            )
        elif e.get("deprecated"):
            errs.append(f"{i}: deprecated in pinned ATT&CK release")
    return errs


def validate_tables() -> list[str]:
    """Referential integrity of the mapping against the pinned table, plus
    version agreement."""
    tech = load_techniques()
    mapping = load_mapping()
    errs = []
    if mapping.get("attack_version") != tech.get("attack_version"):
        errs.append(
            f"mapping attack_version {mapping.get('attack_version')} "
            f"!= table {tech.get('attack_version')}"
        )
    for section in ("capability_map", "category_map"):
        for key, ids in _map_pairs(mapping[section]):
            for e in validate_ids(ids, tech):
                errs.append(f"{section}.{key}: {e}")
    return errs


def main(argv):
    if "--validate-tables" in argv:
        errs = validate_tables()
        for e in errs:
            print(f"✗ {e}", file=sys.stderr)
        print(
            "✓ mapping consistent with pinned ATT&CK table"
            if not errs
            else f"✗ {len(errs)} error(s)"
        )
        return 1 if errs else 0
    if "--validate" in argv:
        ids = [a for a in argv[argv.index("--validate") + 1 :] if not a.startswith("-")]
        errs = validate_ids(ids)
        for e in errs:
            print(f"✗ {e}", file=sys.stderr)
        print(f"✓ {len(ids)} technique ID(s) valid" if not errs else f"✗ {len(errs)} error(s)")
        return 1 if errs else 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
