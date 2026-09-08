#!/usr/bin/env python3
"""Check LLM-proposed pattern-bucket regexes against the rbac-tenancy 'other' tail.

Usage: rbac_bucket_proposal_check.py <proposals.json>
Reports per proposal: compile status, tail matches, coherence sample,
pairwise overlap with other proposals, and combined tail reduction.
"""

import itertools
import json
import re
import sys
from pathlib import Path

props = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
tail = [
    ln.rstrip("\n").split("\t", 2)
    for ln in Path("/tmp/rbac-other-tail.txt").read_text(encoding="utf-8").splitlines(keepends=True)
]
titles = [t[2] for t in tail]

compiled = []
for p in props:
    try:
        rx = re.compile(p["regex"], re.I)
        compiled.append((p["name"], rx))
    except re.error as e:
        print(f"✗ {p['name']}: regex does not compile: {e}")

matches = {}
for name, rx in compiled:
    m = [t for t in titles if rx.search(t)]
    matches[name] = m
    est = next((p["estimated_matches"] for p in props if p["name"] == name), "?")
    print(f"\n### {name}: {len(m)} tail matches (agent estimated {est})")
    for t in m[:8]:
        print(f"    - {t[:110]}")

print("\n### pairwise overlap (first-match-wins: large overlap = merge candidates)")
for (a, _), (b, _) in itertools.combinations(compiled, 2):
    ov = len(set(matches[a]) & set(matches[b]))
    if ov > 10:
        print(f"    {a} ∩ {b} = {ov}")

claimed = set()
for name, _ in compiled:
    claimed |= set(matches[name])
print(
    f"\n### combined: {len(claimed)}/{len(titles)} tail claimed "
    f"({len(claimed) / len(titles):.0%}); residual other = {len(titles) - len(claimed)}"
)
