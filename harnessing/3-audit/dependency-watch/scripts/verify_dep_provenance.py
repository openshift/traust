#!/usr/bin/env python3
"""Auto-verify a dependency finding against the EXACT source manifest(s)
that declared it.

The fleet OSV sweep (harnessing/3-audit/dependency-watch/scripts/fleet_sweep.py) flags a
(package, version) pair as malicious purely from an OSV name+version match.
That match is blind to npm aliasing: a manifest line like

    "legacy-swc-helpers": "npm:@swc/helpers@0.4.14"

declares the LEGITIMATE `@swc/helpers` under a local alias name, NOT the
malicious registry package `legacy-swc-helpers`. The OSV name-match fires
anyway — a false positive that, historically, only manual source inspection
caught. This module is the automated version of that inspection.

`verify_dep(repo_id, ecosystem, package, version, manifest_paths)` fetches
each recorded source manifest, parses it with
`manifest_parsers.parser_for_path` (which ALREADY resolves npm aliases to
their real registry package), and asks: is `package` actually present as a
REAL, alias-resolved dependency?

  * confirmed    — present as the real package in at least one manifest.
  * refuted      — parsed at least one recorded manifest and `package` is
                   NOT present as the real package in ANY of them (e.g. it
                   was only there as an npm alias to a different package).
                   This is exactly the legacy-swc-helpers case.
  * unverifiable — no manifest path recorded, or every fetch/parse failed.
                   NEVER drop a finding on `unverifiable` — the caller keeps
                   it actionable; only a positive `refuted` is a drop.

Security posture: the only network action is a LITERAL
`gh api repos/<org>/<name>/contents/<path>` raw fetch, reusing the vetted
`build_portfolio_graph.fetch_manifest` (argv-list, no shell string, no
secret in argv, on-disk cache). `fetch=` is an injectable seam so tests
never touch the network. org/name/path are charset-gated before any fetch.
"""

from __future__ import annotations

import json
import re

import traust_engine.portfolio.parsers as manifest_parsers

# GitHub owner/repo charset; a hostile repo id never reaches the gh argv.
_OWNER_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _default_fetch(org: str, name: str, path: str, ecosystem: str) -> tuple[str, str]:
    """Literal `gh api repos/<org>/<name>/contents/<path>` raw fetch via the
    vetted build_portfolio_graph.fetch_manifest (argv-list, no shell, disk
    cache). Imported lazily so the module (and its tests, which inject a
    fake `fetch=`) never pull in the graph builder unless a real fetch runs.
    Returns (status, text) with status ok|absent|error|ratelimited."""
    import traust_engine.portfolio.graph as build_portfolio_graph

    return build_portfolio_graph.fetch_manifest(org, name, path, ecosystem)


def _split_repo(repo_id: str) -> tuple[str, str]:
    """(org, name) from a `repo:<org>/<name>` graph node id, or ("","") when
    it does not resolve to a gh-safe owner/repo pair (fail closed)."""
    if not isinstance(repo_id, str):
        return "", ""
    path = repo_id.removeprefix("repo:")
    org, _, name = path.partition("/")
    if not _OWNER_RX.match(org) or not _OWNER_RX.match(name):
        return "", ""
    return org, name


def _path_ok(path: str) -> bool:
    """A recorded manifest path is a repo-relative file path; reject absolute
    paths and `..` traversal before it becomes a gh api URL segment."""
    if not isinstance(path, str) or not path or path.startswith("/"):
        return False
    parts = path.replace("\\", "/").split("/")
    return ".." not in parts and "" not in [p for p in parts]


def _norm(name: str) -> str:
    """Canonical dependency-name key for comparison: lowercase, runs of
    [-_.] collapsed to '-' (mirrors manifest_parsers._pep503). Comparing on
    the normalized form avoids a FALSE `refuted` from pypi/nuget name
    casing/separator differences — a false refutation would silently drop a
    real malicious finding, the worst possible failure here."""
    return re.sub(r"[-_.]+", "-", str(name)).strip("-").lower()


def _version_relation(found: str, recorded: str) -> str:
    if not recorded:
        return "no recorded version to compare"
    f = str(found).lstrip("v^~= ")
    r = str(recorded).lstrip("v^~= ")
    if f == r:
        return f"version {found} matches recorded {recorded}"
    if f.startswith(r) or r.startswith(f):
        return f"version {found} relates to recorded {recorded}"
    return f"version {found} differs from recorded {recorded}"


def _npm_alias_target(text: str, package: str) -> tuple[str, str] | None:
    """If `package` is declared in a package.json dependency section as an
    npm alias (`"package": "npm:<real>@<ver>"`) to a DIFFERENT real package,
    return (real_name, real_version) for the refutation paper trail; else
    None. Reuses manifest_parsers._resolve_npm_alias."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        m = data.get(sect)
        if isinstance(m, dict):
            spec = m.get(package)
            alias = manifest_parsers._resolve_npm_alias(spec)
            if alias and _norm(alias[0]) != _norm(package):
                return alias
    return None


def verify_dep(
    repo_id: str,
    ecosystem: str,
    package: str,
    version: str,
    manifest_paths,
    *,
    fetch=_default_fetch,
) -> dict:
    """Verify a (package, version) finding against its recorded source
    manifests. Returns {status, evidence, manifest} — see module docstring
    for the status contract. `fetch(org, name, path, ecosystem) ->
    (status, text)` is injectable (default: real gh api raw fetch)."""
    org, name = _split_repo(repo_id)
    paths = [p for p in (manifest_paths or []) if _path_ok(p)]
    if not org or not name:
        return {
            "status": "unverifiable",
            "evidence": f"cannot resolve org/name from repo id {repo_id!r}",
            "manifest": None,
        }
    if not paths:
        return {
            "status": "unverifiable",
            "evidence": "no source-manifest path recorded for this finding",
            "manifest": None,
        }

    want = _norm(package)
    parsed_any = False
    fetch_notes: list[str] = []
    alias_note: tuple[str, str, str] | None = None  # (path, real, ver)
    for path in paths:
        try:
            status, text = fetch(org, name, path, ecosystem)
        except Exception as e:
            fetch_notes.append(f"{path}: fetch error ({type(e).__name__})")
            continue
        if status != "ok":
            fetch_notes.append(f"{path}: fetch status {status}")
            continue
        pf = manifest_parsers.parser_for_path(path)
        if pf is None:
            fetch_notes.append(f"{path}: no manifest parser for path")
            continue
        parsed_any = True
        _eco, parse_fn = pf
        _declared, deps = parse_fn(text)
        for dep_name, dep_ver, _indirect in deps:
            if _norm(dep_name) == want:
                return {
                    "status": "confirmed",
                    "evidence": f"{path} declares {dep_name}@{dep_ver} as a "
                    f"real (alias-resolved) dependency; "
                    f"{_version_relation(dep_ver, version)}",
                    "manifest": path,
                }
        # Present in the recorded manifest, but not as the real package.
        # Capture the npm-alias masking (the legacy-swc-helpers shape) for
        # the refutation paper trail.
        if ecosystem == "npm" and alias_note is None:
            at = _npm_alias_target(text, package)
            if at:
                alias_note = (path, at[0], at[1])

    if parsed_any:
        if alias_note:
            apath, real, rver = alias_note
            return {
                "status": "refuted",
                "evidence": f"{package} appears in {apath} only as an npm "
                f"alias to {real}@{rver} "
                f'("npm:{real}@{rver}"), not as the real '
                f"registry package {package} — false positive",
                "manifest": apath,
            }
        checked = ", ".join(paths)
        return {
            "status": "refuted",
            "evidence": f"{package} is not declared as a real "
            f"(alias-resolved) dependency in any recorded "
            f"manifest ({checked})",
            "manifest": paths[0],
        }
    return {
        "status": "unverifiable",
        "evidence": "no recorded manifest could be fetched and parsed"
        + (": " + "; ".join(fetch_notes) if fetch_notes else ""),
        "manifest": None,
    }
