#!/usr/bin/env python3
"""Route×guard matrix enumerator (structural-lane pre-scan, Phase B2/D2).

Enumerates a checkout's HTTP route registrations and the authentication/
authorization guards actually applied to each, emitting the route×guard
matrix as a judged worklist — the enforcement-asymmetry class (one route
in a family guarded, its sibling not) was ~80% false-negative for
narrative review lanes (awx-false-negative-analysis: 4 of 5 missed highs;
deep-fn-technique-plan §1.3). Narrative lanes sample routes; an
enumerated matrix makes "which registrations lack the guard their
siblings carry" a mechanical question the model then judges.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md). An unguarded row is not a
finding: the route may be intentionally public, guarded at the gateway,
or dead. The judging protocol lives in secure-code-audit SKILL.md
(route×guard pre-scan section) — and the lane may NOT close with
unjudged rows: the un-judged remainder is a coverage_gap, not silence.

Framework families (v1, per plan Phase B2 — two families first):
  go-http     net/http HandleFunc/Handle, gorilla-mux
              HandleFunc/Handle(+.Methods), chi/echo/gin-style verb
              registrations (Get/GET/Post/POST/...), plus receiver-scoped
              `.Use(mw)` middleware and guard-wrapped handler expressions.
  django-drf  urls.py path()/re_path()/url() registrations; class-based
              views' permission_classes/authentication_classes;
              @login_required/@permission_required/@api_view decorators;
              REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES baseline;
              AllowAny as an explicit unguard marker.

Other web frameworks detected in the tree (express, fastapi, flask,
spring) are emitted as coverage_gaps so the audit's negative_results can
name what this enumerator did not cover.

Guard recognition is NAME-BASED and deliberately over-inclusive
(anything matching auth/rbac/token/permission/... shapes counts as a
guard); the judge decides whether a recognized guard actually enforces.
Symbol-index enrichment: when a per-run index exists
(`traust build symbol-index`), handler definitions are resolved to
file:line through it; without one, the registration site is the anchor.

Usage:
    python3 enumerate_route_guards.py <repo-path> [--out <file>]
                                      [--index <symbols.db>]

Output defaults to <repo-basename>-route-guards.json in the CWD.
Exit 0 on a completed enumeration (gaps included); 1 on bad input.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sqlite3
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT

GUARD_RX = re.compile(
    r"(?i)(auth[nz]?|authenticate|authoriz|login|rbac|permission|"
    r"require|protect|verify|token|jwt|oidc|oauth|session|csrf|"
    r"admin[_A-Z]|acl|scope|role|guard|secure)"
)

# names that look like guards but explicitly DISABLE guarding — these mark
# a row as judgement-required even when other "guards" match
UNGUARD_RX = re.compile(
    r"(?i)(allowany|allow_any|anonymous|skipauth|skip_auth|noauth|"
    r"no_auth|unauthenticated|public|insecureskip)"
)

SKIP_DIRS = {
    ".git",
    "vendor",
    "node_modules",
    "third_party",
    "testdata",
    ".tox",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
}
TEST_NAME_RX = re.compile(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)")
MAX_FILE_BYTES = 2 * 1024 * 1024

GO_VERBS = (
    "Get",
    "Post",
    "Put",
    "Delete",
    "Patch",
    "Head",
    "Options",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
)

GO_HANDLEFUNC_RX = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>HandleFunc|Handle)\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
GO_VERB_RX = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>" + "|".join(GO_VERBS) + r")\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
GO_USE_RX = re.compile(r"(?P<recv>[\w.]+)\.Use\(\s*(?P<mws>[^)]+?)\s*\)")

PY_URL_RX = re.compile(
    r'(?:path|re_path|url)\(\s*r?["\'](?P<pattern>[^"\']*)["\']\s*,\s*'
    r"(?P<view>[\w.]+(?:\.as_view\(\))?)"
)
PY_PERM_RX = re.compile(r"permission_classes\s*=\s*[\[\(](?P<perms>[^\]\)]*)[\]\)]")
PY_DECOR_RX = re.compile(r"^\s*@(?P<name>[\w.]+)", re.M)

OTHER_FRAMEWORKS = [
    (
        "express",
        re.compile(
            r'\brequire\(["\']express["\']\)|'
            r'from\s+["\']express["\']'
        ),
    ),
    ("fastapi", re.compile(r"\bfrom fastapi import|\bFastAPI\(")),
    ("flask", re.compile(r"\bfrom flask import|\bFlask\(__name__")),
    ("spring", re.compile(r"@(RestController|RequestMapping|GetMapping)")),
]


def _walk(repo: Path, suffixes: tuple[str, ...]):
    for p in sorted(repo.rglob("*")):
        if not p.is_file() or p.is_symlink() or p.suffix not in suffixes:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
            continue
        if TEST_NAME_RX.search(p.name.lower()):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _guards_in(expr: str) -> list[str]:
    """Names inside an expression that look like guards (dedup, ordered)."""
    out, seen = [], set()
    for tok in re.findall(r"[A-Za-z_][\w.]*", expr):
        if GUARD_RX.search(tok) and not UNGUARD_RX.search(tok) and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _unguards_in(expr: str) -> list[str]:
    return sorted({t for t in re.findall(r"[A-Za-z_][\w.]*", expr) if UNGUARD_RX.search(t)})


def make_row(family, method, pattern, handler, path, line, guards, scope_guards, unguards):
    all_guards = list(dict.fromkeys(guards + scope_guards))
    row = {
        "family": family,
        "method": method,
        "pattern": pattern,
        "handler": {"expr": handler[:200], "path": path, "line": line},
        "guards": guards,
        "scope_guards": scope_guards,
        "registration": {"path": path, "line": line},
        "judgement_required": not all_guards or bool(unguards),
    }
    if unguards:
        row["unguard_markers"] = unguards
    return row


# --------------------------------------------------------------------------
# family: go-http
# --------------------------------------------------------------------------


def enumerate_go(repo: Path, rows: list):
    for f in _walk(repo, (".go",)):
        text = _read(f)
        if (
            ".HandleFunc(" not in text
            and ".Handle(" not in text
            and not any(f".{v}(" in text for v in GO_VERBS)
        ):
            continue
        rel = str(f.relative_to(repo))
        # receiver-scoped middleware: r.Use(authMW) anywhere in the file
        # applies to that receiver's registrations (over-approximation —
        # the judge sees scope_guards separately from direct guards)
        scope: dict[str, list[str]] = {}
        unguard_scope: dict[str, list[str]] = {}
        for m in GO_USE_RX.finditer(text):
            recv = m.group("recv")
            scope.setdefault(recv, []).extend(_guards_in(m.group("mws")))
            unguard_scope.setdefault(recv, []).extend(_unguards_in(m.group("mws")))
        for rx in (GO_HANDLEFUNC_RX, GO_VERB_RX):
            for m in rx.finditer(text):
                recv = m.group("recv")
                if recv in ("t", "b", "suite"):  # test receivers
                    continue
                handler = m.group("handler")
                line = text[: m.start()].count("\n") + 1
                rows.append(
                    make_row(
                        "go-http",
                        m.group("method"),
                        m.group("pattern"),
                        handler,
                        rel,
                        line,
                        guards=_guards_in(handler),
                        scope_guards=list(dict.fromkeys(scope.get(recv, []))),
                        unguards=_unguards_in(handler) + unguard_scope.get(recv, []),
                    )
                )


# --------------------------------------------------------------------------
# family: django-drf
# --------------------------------------------------------------------------


def _view_guard_index(repo: Path) -> dict[str, dict]:
    """Map view/class name -> guards from its definition site."""
    idx: dict[str, dict] = {}
    for f in _walk(repo, (".py",)):
        text = _read(f)
        rel = str(f.relative_to(repo))
        for m in re.finditer(r"^class\s+(?P<name>\w+)\s*\((?P<bases>[^)]*)\)\s*:", text, re.M):
            body_start = m.end()
            nxt = re.search(r"^\S", text[body_start:], re.M)
            body = text[body_start : body_start + nxt.start()] if nxt else text[body_start:]
            perms = PY_PERM_RX.search(body)
            guards = _guards_in(perms.group("perms")) if perms else []
            unguards = _unguards_in(perms.group("perms")) if perms else []
            idx[m.group("name")] = {
                "guards": guards,
                "unguards": unguards,
                "path": rel,
                "line": text[: m.start()].count("\n") + 1,
                "has_perm_attr": bool(perms),
            }
        for m in re.finditer(
            r"(?P<decos>(?:^\s*@[\w.()'\", =\[\]]+\n)+)"
            r"^\s*def\s+(?P<name>\w+)\s*\(",
            text,
            re.M,
        ):
            decos = m.group("decos")
            guards = _guards_in(decos)
            unguards = _unguards_in(decos)
            if guards or unguards:
                idx[m.group("name")] = {
                    "guards": guards,
                    "unguards": unguards,
                    "path": rel,
                    "line": text[: m.start()].count("\n") + 1,
                    "has_perm_attr": True,
                }
    return idx


def _drf_default_guards(repo: Path) -> list[str]:
    for f in _walk(repo, (".py",)):
        if "settings" not in f.name.lower() and "settings" not in str(f.parent).lower():
            continue
        text = _read(f)
        m = re.search(r"DEFAULT_PERMISSION_CLASSES.*?[\[\(](?P<perms>[^\]\)]*)[\]\)]", text, re.S)
        if m:
            return _guards_in(m.group("perms"))
    return []


def enumerate_django(repo: Path, rows: list):
    url_files = [f for f in _walk(repo, (".py",)) if "url" in f.name.lower()]
    if not url_files:
        return
    view_idx = _view_guard_index(repo)
    defaults = _drf_default_guards(repo)
    for f in url_files:
        text = _read(f)
        rel = str(f.relative_to(repo))
        for m in PY_URL_RX.finditer(text):
            view = m.group("view")
            base = view.split(".")[0].replace(".as_view()", "")
            info = (
                view_idx.get(base)
                or view_idx.get(view.replace(".as_view()", "").split(".")[-1])
                or {}
            )
            line = text[: m.start()].count("\n") + 1
            rows.append(
                make_row(
                    "django-drf",
                    "any",
                    m.group("pattern") or "/",
                    view,
                    info.get("path", rel),
                    info.get("line", line),
                    guards=info.get("guards", []),
                    scope_guards=[] if info.get("has_perm_attr") else defaults,
                    unguards=info.get("unguards", []),
                )
            )


# --------------------------------------------------------------------------
# asymmetry grouping + symbol-index enrichment + gaps
# --------------------------------------------------------------------------


def find_asymmetries(rows: list) -> list:
    """Groups (same file, same family) where guard coverage differs —
    the AWX miss shape: one registration wrapped, its sibling bare."""
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r["family"], r["registration"]["path"]), []).append(r)
    out = []
    for (family, path), members in sorted(groups.items()):
        guarded = [r for r in members if r["guards"] or r["scope_guards"]]
        bare = [r for r in members if not r["guards"] and not r["scope_guards"]]
        if guarded and bare:
            out.append(
                {
                    "family": family,
                    "path": path,
                    "guarded": [r["pattern"] for r in guarded],
                    "unguarded": [r["pattern"] for r in bare],
                }
            )
            for r in bare:
                r["judgement_required"] = True
                r["asymmetry"] = True
    return out


def enrich_from_index(rows: list, index_db: Path):
    try:
        con = sqlite3.connect(f"file:{index_db}?mode=ro", uri=True)
    except sqlite3.Error:
        return
    try:
        for r in rows:
            name = re.sub(r"\(.*$", "", r["handler"]["expr"]).split(".")[-1]
            if not re.match(r"^\w+$", name):
                continue
            try:
                hit = con.execute(
                    "SELECT path, line FROM symbols WHERE name = ? "
                    "AND kind IN ('func', 'function', 'method') LIMIT 1",
                    (name,),
                ).fetchone()
            except sqlite3.Error:
                return
            if hit:
                r["handler"]["resolved"] = {"path": hit[0], "line": hit[1]}
    finally:
        con.close()


def detect_other_frameworks(repo: Path, gaps: list):
    hits: dict[str, str] = {}
    for f in _walk(repo, (".js", ".ts", ".py", ".java", ".kt")):
        text = _read(f)
        for name, rx in OTHER_FRAMEWORKS:
            if name not in hits and rx.search(text):
                hits[name] = str(f.relative_to(repo))
    for name, path in sorted(hits.items()):
        gaps.append(
            {
                "system": name,
                "reason": f"{name} routes detected but v1 enumerates only "
                f"go-http and django-drf — this family's route×guard "
                f"matrix is UNENUMERATED",
                "evidence": path,
            }
        )


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def enumerate_routes(repo: Path, index_db: Path | None = None) -> dict:
    rows: list[dict] = []
    gaps: list[dict] = []
    enumerate_go(repo, rows)
    enumerate_django(repo, rows)
    asym = find_asymmetries(rows)
    if index_db and index_db.is_file():
        enrich_from_index(rows, index_db)
    detect_other_frameworks(repo, gaps)

    rows.sort(
        key=lambda r: (
            not r["judgement_required"],
            not r.get("asymmetry", False),
            r["registration"]["path"],
            r["registration"]["line"],
        )
    )
    by_family: dict[str, int] = {}
    for r in rows:
        by_family[r["family"]] = by_family.get(r["family"], 0) + 1
    return {
        "artifact": "route-guard-matrix",
        "repo": repo.name,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "routes": rows,
        "asymmetries": asym,
        "coverage_gaps": gaps,
        "stats": {
            "total": len(rows),
            "judgement_required": sum(1 for r in rows if r["judgement_required"]),
            "asymmetry_rows": sum(1 for r in rows if r.get("asymmetry")),
            "by_family": by_family,
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", type=Path, help="local checkout to enumerate")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--index", type=Path, default=None, help="optional symbols.db from build_symbol_index.py"
    )
    args = ap.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 1
    result = enumerate_routes(repo, args.index)
    out = args.out or Path(f"{repo.name}-route-guards.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    s = result["stats"]
    print(
        f"{result['repo']}: {s['total']} routes "
        f"({s['judgement_required']} to judge, "
        f"{s['asymmetry_rows']} in asymmetry groups), "
        f"{len(result['asymmetries'])} asymmetry groups, "
        f"{len(result['coverage_gaps'])} coverage gaps -> {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
