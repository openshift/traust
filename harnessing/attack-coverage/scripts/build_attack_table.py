#!/usr/bin/env python3
"""build_attack_table.py — vendor a pinned, distilled MITRE ATT&CK subset.

Downloads ONE pinned release of the Enterprise ATT&CK STIX bundle from
mitre-attack/attack-stix-data, verifies its sha256 when a pin is recorded,
and distills it to tables/attack-techniques.json: technique ID, name,
tactics, platforms, containers-matrix membership, deprecated/revoked flags,
plus the mitigation (course-of-action) M-IDs. The distilled table is the
ONLY ATT&CK artifact committed to the repo (the raw bundle is ~50 MB) and
is the single source every harness component validates technique IDs
against. Re-running against the same pin is byte-stable.

To move to a new ATT&CK release: bump ATTACK_VERSION, run with
--refresh-pin, review the diff, commit.

Terms of use: ATT&CK is (c) The MITRE Corporation, used with attribution
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

Usage:  python3 build_attack_table.py [--refresh-pin]
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent
TABLES = SKILL_DIR / "tables"

ATTACK_VERSION = "19.1"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    f"attack-stix-data/master/enterprise-attack/"
    f"enterprise-attack-{ATTACK_VERSION}.json"
)
PIN_FILE = TABLES / "attack-bundle.sha256"
OUT = TABLES / "attack-techniques.json"

ATTRIBUTION = (
    "MITRE ATT&CK(R) is a registered trademark of The MITRE "
    "Corporation. (c) The MITRE Corporation. This work is "
    "reproduced and distributed with the permission of The MITRE "
    "Corporation under the ATT&CK Terms of Use "
    "(https://attack.mitre.org/resources/legal-and-branding/"
    "terms-of-use/)."
)


def ext_id(obj):
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def main():
    refresh = "--refresh-pin" in sys.argv
    print(f"fetching Enterprise ATT&CK v{ATTACK_VERSION} …")
    raw = urllib.request.urlopen(BUNDLE_URL, timeout=120).read()
    sha = hashlib.sha256(raw).hexdigest()
    if PIN_FILE.exists() and not refresh:
        pinned = PIN_FILE.read_text().split()[0]
        if sha != pinned:
            print(
                f"FATAL: bundle sha256 {sha} != pinned {pinned} "
                f"(pass --refresh-pin only for a deliberate upgrade)",
                file=sys.stderr,
            )
            return 1
    bundle = json.loads(raw)

    techniques, mitigations = {}, {}
    revoked_by = {}
    for o in bundle["objects"]:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            revoked_by[o["source_ref"]] = o["target_ref"]
    stix_to_tid = {
        o["id"]: ext_id(o) for o in bundle["objects"] if o.get("type") == "attack-pattern"
    }
    for o in bundle["objects"]:
        t = o.get("type")
        tid = ext_id(o)
        if not tid:
            continue
        if t == "attack-pattern":
            techniques[tid] = {
                "name": o.get("name"),
                "tactics": sorted(
                    {
                        p["phase_name"]
                        for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"
                    }
                ),
                "platforms": sorted(o.get("x_mitre_platforms", [])),
                "containers": "Containers" in o.get("x_mitre_platforms", []),
                "deprecated": bool(o.get("x_mitre_deprecated")),
                "revoked": bool(o.get("revoked")),
                "revoked_by": stix_to_tid.get(revoked_by.get(o["id"])),
            }
        elif t == "course-of-action" and tid.startswith("M"):
            mitigations[tid] = {
                "name": o.get("name"),
                "deprecated": bool(o.get("x_mitre_deprecated")),
            }

    if len(techniques) < 500:
        print(
            f"FATAL: only {len(techniques)} techniques distilled — bundle looks wrong",
            file=sys.stderr,
        )
        return 1

    table = {
        "source": "MITRE ATT&CK Enterprise (mitre-attack/attack-stix-data)",
        "attack_version": ATTACK_VERSION,
        "bundle_url": BUNDLE_URL,
        "bundle_sha256": sha,
        "attribution": ATTRIBUTION,
        "counts": {"techniques": len(techniques), "mitigations": len(mitigations)},
        "techniques": dict(sorted(techniques.items())),
        "mitigations": dict(sorted(mitigations.items())),
    }
    TABLES.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(table, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    PIN_FILE.write_text(f"{sha}  enterprise-attack-{ATTACK_VERSION}.json\n")
    print(
        f"wrote {OUT} ({len(techniques)} techniques, "
        f"{len(mitigations)} mitigations, ATT&CK v{ATTACK_VERSION})"
    )
    print(f"pinned {PIN_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
