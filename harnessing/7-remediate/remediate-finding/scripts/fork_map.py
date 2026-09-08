#!/usr/bin/env python3
"""
Fork map for the remediate-finding harness.

Maps an upstream repository URL to the private fork where automated
remediation patches are pushed. Forks are *private mirrors* (not GitHub
network forks — public repos cannot be forked private) so that embargoed
fixes never appear on a public timeline.

Resolution order:
  1. Explicit entry in ``FORKS`` below.
  2. ``analysis-results/remediations/_manifest/fork-map.csv`` if present
     (columns: upstream_url, fork_url, host, base_ref, visibility).
  3. Heuristic: ``https://github.com/<org>/<repo>`` →
     ``https://github.com/<fork_org>/<repo>``  (must already
     exist — this module never creates forks; that is ``ensure_fork.sh``'s job).

CLI:
  fork_map.py <upstream-url>            → JSON {fork_url, host, base_ref, …}
  fork_map.py --list                    → all known mappings as JSON lines
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent

_ANALYSIS_ROOT: Path | None = None


def configure_paths(analysis_results: Path) -> None:
    """Set analysis-results root for fork-map.csv resolution (call from main())."""
    global _ANALYSIS_ROOT
    _ANALYSIS_ROOT = analysis_results


def _fork_map_csv() -> Path:
    if _ANALYSIS_ROOT is not None:
        root = _ANALYSIS_ROOT
    else:
        from traust.context import resolve_results_root

        root = resolve_results_root()
    return root / "remediations" / "_manifest" / "fork-map.csv"


# Default branch namespace for fixes. Neutral so the tool carries no
# campaign name; deployments that want one set FIX_BRANCH_PREFIX.
_DEFAULT_FIX_PREFIX = os.environ.get("FIX_BRANCH_PREFIX", "fix")


# The locked-down org that hosts every private mirror is the adopter's
# (remediation.yaml `fork_org`, or HARNESS_FORK_ORG). Org admins only;
# members_can_create_*=False so ensure_fork.sh must use the /orgs/{org}/repos
# endpoint (admin bypass). Resolved lazily so importing this module never
# requires a config home.
def default_fork_owner() -> str:
    from traust.context import require_fork_org

    return require_fork_org()


@dataclass
class Fork:
    upstream_url: str
    fork_url: str
    host: str = "github"  # github | gitlab | gitlab-cee | other
    visibility: str = "private"
    #: Branch in the fork to cut fix branches from.  ``__audited__`` is a
    #: sentinel meaning "use metadata.audited_commit from the manifest row"
    #: so line numbers in the finding resolve exactly.
    base_ref: str = "__audited__"
    #: Branch namespace for fix branches. A campaign codename is deployment
    #: config, not a shipped constant — override per repo in fork-map.csv,
    #: or globally with FIX_BRANCH_PREFIX.
    fix_branch_prefix: str = _DEFAULT_FIX_PREFIX
    notes: str = ""

    def fix_branch(self, finding_id: str, slug: str = "") -> str:
        fid = re.sub(r"[^A-Za-z0-9]+", "-", finding_id).strip("-").lower()
        slug = re.sub(r"[^A-Za-z0-9]+", "-", slug).strip("-").lower()[:40]
        parts = [self.fix_branch_prefix, fid]
        if slug:
            parts.append(slug)
        return "/".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Explicit pilot entries.  Keep this list short — bulk mappings belong in
# fork-map.csv so they can be regenerated.
# ---------------------------------------------------------------------------
#: Hardcoded overrides. Prefer ``fork-map.csv`` (resolution tier 2) for
#: campaign data so pilots can be swapped without a harness code change.
FORKS: dict[str, Fork] = {}


_GH = re.compile(r"^https://github\.com/(?P<org>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")
_GL = re.compile(r"^https://(?P<host>gitlab[^/]+)/(?P<org>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def _norm(url: str) -> str:
    return url.rstrip("/").removesuffix(".git")


def _load_csv() -> dict[str, Fork]:
    out: dict[str, Fork] = {}
    fork_map_csv = _fork_map_csv()
    if not fork_map_csv.is_file():
        return out
    with fork_map_csv.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            up = _norm(r["upstream_url"])
            out[up] = Fork(
                upstream_url=up,
                fork_url=_norm(r["fork_url"]),
                host=r.get("host") or "github",
                visibility=r.get("visibility") or "private",
                base_ref=r.get("base_ref") or "__audited__",
                fix_branch_prefix=(r.get("fix_branch_prefix") or _DEFAULT_FIX_PREFIX),
                notes=r.get("notes", ""),
            )
    return out


def resolve(upstream_url: str) -> Fork:
    """Resolve an upstream URL to its private fork.

    Raises ``KeyError`` if no mapping exists and no heuristic applies.
    """
    key = _norm(upstream_url)
    if key in FORKS:
        return FORKS[key]
    csv_map = _load_csv()
    if key in csv_map:
        return csv_map[key]
    if m := _GH.match(key):
        return Fork(
            upstream_url=key,
            fork_url=f"https://github.com/{default_fork_owner()}/{m['repo']}",
            host="github",
            notes="heuristic — verify fork exists before use",
        )
    if m := _GL.match(key):
        host = "gitlab-cee" if "cee.redhat.com" in m["host"] else "gitlab"
        # Internal GitLab repos ARE the downstream fork; remediate in-place.
        return Fork(
            upstream_url=key,
            fork_url=key,
            host=host,
            visibility="internal",
            notes="private-forge repo — treated as its own downstream fork",
        )
    raise KeyError(f"No fork mapping for {upstream_url!r}")


def all_known() -> dict[str, Fork]:
    out = dict(FORKS)
    out.update(_load_csv())
    return out


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--list":
        for f in all_known().values():
            print(json.dumps(asdict(f)))
        return 0
    if len(argv) != 1:
        print("usage: fork_map.py <upstream-url> | --list", file=sys.stderr)
        return 2
    try:
        f = resolve(argv[0])
    except KeyError as e:
        print(json.dumps({"error": str(e)}))
        return 1
    print(json.dumps(asdict(f)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
