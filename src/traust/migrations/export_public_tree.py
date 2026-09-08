#!/usr/bin/env python3
"""One-shot public export of the Traust repositories (2026-09-08).

Produces, for each repository named in ``$TRAUST_CONFIG_HOME/export.yaml``, a
fresh publication tree from the **tracked files** of a working checkout:

1. ``git archive HEAD`` → ``<out>/<repo>/`` (tracked files only; nothing
   ignored or untracked can leak).
2. Strip the paths the deployment names (its CI/build plumbing — decision D1).
3. Rewrite every occurrence of a private forge base URL to the public one in
   every text file — dependency pins in ``pyproject.toml`` and ``uv.lock``,
   OCI ``image.source`` labels, doc links (decision D2/D2a).
4. Truncate ``CHANGELOG.md`` at the export boundary with a provenance note
   (decision D3).
5. ``git init`` + one commit by the configured author: a fresh history
   (decision D6). Nothing is pushed; the source checkout is never touched.
6. Run the pre-publication scrub gate (``traust.cli.scan_internal_refs``)
   over the produced tree with the deployment vocabulary and **no**
   expected-internal allowance, and write ``<out>/export-report.json`` +
   ``export-report.md``.

Sequencing note for the real publish: a repo's ``uv.lock`` records the
commit hash behind each git-tag pin. Fresh histories mean new hashes, so
after publishing a dependency you must ``uv lock`` in the dependent's
exported tree before publishing it. The dry-run rewrites lock URLs but
cannot regenerate hashes; the report says so per repo.

    python3 -m traust.migrations.export_public_tree --workspace .. --out /tmp/export
    python3 -m traust.migrations.export_public_tree --repos traust-contracts --no-scan
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from traust.paths import config_path

TEXT_SNIFF = 4096


def load_export_config(path: Path | None = None) -> dict:
    p = path or config_path("export.yaml")
    doc = yaml.safe_load(Path(p).read_text(encoding="utf-8")) or {}
    for key in ("public_base_url", "private_base_urls", "repos"):
        if not doc.get(key):
            raise SystemExit(f"{p}: `{key}` is required")
    doc.setdefault("strip", [])
    doc.setdefault("changelog", {"mode": "truncate", "note": ""})
    doc.setdefault("commit_author", "Traust maintainers <maintainers@example.org>")
    doc["public_base_url"] = str(doc["public_base_url"]).rstrip("/")
    doc["private_base_urls"] = [str(u).rstrip("/") for u in doc["private_base_urls"]]
    return doc


def _run(argv: list[str], cwd: Path | None = None, env: dict | None = None) -> str:
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise SystemExit(f"{' '.join(argv)} failed ({p.returncode}): {p.stderr.strip()}")
    return p.stdout


def _is_text(p: Path) -> bool:
    try:
        return b"\0" not in p.read_bytes()[:TEXT_SNIFF]
    except OSError:
        return False


def archive_tracked(src_repo: Path, dest: Path) -> int:
    """Copy HEAD's tracked files into ``dest``; return the file count."""
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "-C", str(src_repo), "archive", "--format=tar", "HEAD"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"git archive failed for {src_repo}: {proc.stderr.decode(errors='replace')}"
        )
    subprocess.run(["tar", "-x", "-C", str(dest)], input=proc.stdout, check=True)
    return sum(1 for p in dest.rglob("*") if p.is_file() or p.is_symlink())


def strip_paths(tree: Path, patterns: list[str]) -> list[str]:
    removed: list[str] = []
    for pat in patterns:
        target = tree / pat.rstrip("/")
        if pat.endswith("/") and target.is_dir():
            shutil.rmtree(target)
            removed.append(pat)
        elif target.is_file() or target.is_symlink():
            target.unlink()
            removed.append(pat)
    return removed


# GitLab web paths use a `/-/` separator that GitHub does not. A link rewritten
# from a GitLab base to a GitHub base keeps the GitLab path and 404s
# (`.../traust/-/blob/main/docs/x.md`). Convert the common ones; `/-/raw/`
# has no GitHub equivalent under the same host and is left for review.
_GITLAB_PATH_FIXES = (
    ("/-/blob/", "/blob/"),
    ("/-/tree/", "/tree/"),
    ("/-/commit/", "/commit/"),
    ("/-/commits/", "/commits/"),
    ("/-/tags/", "/tags/"),
    ("/-/releases/", "/releases/"),
    ("/-/merge_requests/", "/pulls/"),
    ("/-/issues/", "/issues/"),
)


def _fix_forge_paths(text: str, public: str) -> str:
    """After a base-URL rewrite, turn GitLab `/-/<kind>/` paths under the public
    base into GitHub paths. Only touches URLs that start with ``public``."""
    if "github.com" not in public or public not in text:
        return text
    out: list[str] = []
    i = 0
    while True:
        j = text.find(public, i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = j + len(public)
        while k < len(text) and not text[k].isspace() and text[k] not in ")\"'<>`]":
            k += 1
        url = text[j:k]
        for a, b in _GITLAB_PATH_FIXES:
            url = url.replace(a, b)
        out.append(url)
        i = k
    return "".join(out)


def rewrite_urls(tree: Path, private: list[str], public: str) -> dict[str, int]:
    """Replace ``<private>/<repo>`` with ``<public>/<repo>`` in every text file,
    then convert GitLab web paths under the public base to GitHub form.

    Returns ``{relative_path: replacements}`` for files that changed.
    """
    changed: dict[str, int] = {}
    for p in tree.rglob("*"):
        if not p.is_file() or p.is_symlink() or ".git" in p.parts or not _is_text(p):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        new, n = text, 0
        for base in private:
            if base in new:
                n += new.count(base)
                new = new.replace(base, public)
        if n:
            new = _fix_forge_paths(new, public)
            p.write_text(new, encoding="utf-8")
            changed[str(p.relative_to(tree))] = n
    return changed


def truncate_changelog(tree: Path, cfg: dict, version: str | None) -> bool:
    cl = tree / "CHANGELOG.md"
    if cfg.get("mode", "truncate") != "truncate" or not cl.is_file():
        return False
    note = " ".join(str(cfg.get("note", "")).split())
    today = _dt.datetime.now(_dt.UTC).date().isoformat()
    ver = f" — v{version}" if version else ""
    cl.write_text(
        "# Changelog\n\n"
        f"## Public release{ver} — {today}\n\n"
        f"{note}\n\n"
        "Changes from this release onward are recorded here.\n",
        encoding="utf-8",
    )
    return True


def read_version(tree: Path) -> str | None:
    """Repo-root ``VERSION``; else the per-component ``<dir>/VERSION`` files a
    multi-language repo carries (traust-sdk: ``go/VERSION``, …), rendered as
    ``go 0.11.0, python 0.3.0``. None when neither exists."""
    v = tree / "VERSION"
    if v.is_file():
        return v.read_text(encoding="utf-8").strip() or None
    parts = []
    for sub in sorted(p for p in tree.iterdir() if p.is_dir() and not p.name.startswith(".")):
        pv = sub / "VERSION"
        if pv.is_file():
            val = pv.read_text(encoding="utf-8").strip()
            if val:
                parts.append(f"{sub.name} {val}")
    return ", ".join(parts) or None


def fresh_history(tree: Path, author: str, message: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": author.split("<")[0].strip(),
        "GIT_AUTHOR_EMAIL": author.split("<")[-1].rstrip(">").strip(),
        "GIT_COMMITTER_NAME": author.split("<")[0].strip(),
        "GIT_COMMITTER_EMAIL": author.split("<")[-1].rstrip(">").strip(),
    }
    _run(["git", "init", "-q", "-b", "main"], cwd=tree, env=env)
    _run(["git", "add", "-A"], cwd=tree, env=env)
    _run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", message], cwd=tree, env=env)
    return _run(["git", "rev-parse", "--short", "HEAD"], cwd=tree, env=env).strip()


def scan_tree(tree: Path, vocabulary: str | None) -> list[dict]:
    from traust.cli.scan_internal_refs import all_rules, scan_repo

    rules = all_rules(vocabulary)
    return scan_repo(tree, 10_000_000, rules)


def export_repo(
    name: str, workspace: Path, out: Path, cfg: dict, *, scan: bool, vocabulary: str | None
) -> dict:
    src = workspace / name
    if not (src / ".git").exists():
        raise SystemExit(f"{src}: not a git repo")
    dest = out / name
    if dest.exists():
        shutil.rmtree(dest)
    src_head = _run(["git", "-C", str(src), "rev-parse", "--short", "HEAD"]).strip()
    dirty = _run(["git", "-C", str(src), "status", "--porcelain"]).strip()
    n_files = archive_tracked(src, dest)
    removed = strip_paths(dest, cfg["strip"])
    rewritten = rewrite_urls(dest, cfg["private_base_urls"], cfg["public_base_url"])
    version = read_version(dest)
    truncated = truncate_changelog(dest, cfg["changelog"], version)
    label = f"v{version}" if version and " " not in version else (version or "unversioned")
    commit = fresh_history(dest, cfg["commit_author"], f"{name} {label} — public release")
    rec = {
        "repo": name,
        "source_head": src_head,
        "source_dirty": bool(dirty),
        "version": version,
        "files_archived": n_files,
        "stripped": removed,
        "url_rewrites": rewritten,
        "changelog_truncated": truncated,
        "lock_needs_regeneration": (dest / "uv.lock").is_file() and bool(rewritten.get("uv.lock")),
        "export_commit": commit,
    }
    if scan:
        findings = scan_tree(dest, vocabulary)
        rec["scan"] = {
            "block": sum(1 for f in findings if f["tier"] == "block"),
            "review": sum(1 for f in findings if f["tier"] == "review"),
            "note": sum(1 for f in findings if f["tier"] == "note"),
            "findings": [
                {k: f.get(k) for k in ("tier", "rule", "file", "line", "match", "why")}
                for f in findings
                if f["tier"] != "note"
            ],
        }
    return rec


def render_md(report: dict) -> str:
    lines = [
        f"# Public export dry-run — {report['generated']}",
        "",
        f"Config: `{report['config']}` · public base `{report['public_base_url']}`",
        "",
        "| Repo | Source HEAD | Version | Files | Stripped | URL rewrites (files) | CHANGELOG | Lock regen | Block | Review | Note |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in report["repos"]:
        s = r.get("scan", {})
        lines.append(
            f"| `{r['repo']}` | `{r['source_head']}`{' (dirty)' if r['source_dirty'] else ''} | {r['version'] or '—'} | "
            f"{r['files_archived']} | {', '.join(r['stripped']) or '—'} | {len(r['url_rewrites'])} | "
            f"{'truncated' if r['changelog_truncated'] else 'kept'} | {'yes' if r['lock_needs_regeneration'] else 'no'} | "
            f"{s.get('block', '—')} | {s.get('review', '—')} | {s.get('note', '—')} |"
        )
    lines += ["", "## Block / review hits in the exported trees (no allowances)", ""]
    any_hit = False
    for r in report["repos"]:
        for f in r.get("scan", {}).get("findings", []):
            any_hit = True
            lines.append(
                f"- **{f['tier']}** `{f['rule']}` `{r['repo']}/{f['file']}:{f.get('line')}` — `{str(f.get('match') or '')[:100]}`"
            )
    if not any_hit:
        lines.append("_none_")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--config", type=Path, help="export.yaml (default: $TRAUST_CONFIG_HOME/export.yaml)"
    )
    ap.add_argument(
        "--workspace",
        type=Path,
        default=Path("..").resolve(),
        help="directory holding the source checkouts (default: parent of cwd)",
    )
    ap.add_argument(
        "--out", type=Path, required=True, help="output directory for the exported trees"
    )
    ap.add_argument(
        "--repos", nargs="*", help="subset of the configured repos, in the configured order"
    )
    ap.add_argument("--no-scan", action="store_true")
    ap.add_argument("--vocabulary", help="scrub vocabulary YAML (default: the deployment's)")
    args = ap.parse_args(argv)

    cfg = load_export_config(args.config)
    repos = [r for r in cfg["repos"] if not args.repos or r in args.repos]
    args.out.mkdir(parents=True, exist_ok=True)
    report = {
        "generated": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "config": str(args.config or config_path("export.yaml")),
        "public_base_url": cfg["public_base_url"],
        "repos": [],
    }
    for name in repos:
        print(f"[export] {name} …", file=sys.stderr)
        report["repos"].append(
            export_repo(
                name,
                args.workspace.resolve(),
                args.out.resolve(),
                cfg,
                scan=not args.no_scan,
                vocabulary=args.vocabulary,
            )
        )
    (args.out / "export-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.out / "export-report.md").write_text(render_md(report), encoding="utf-8")
    for r in report["repos"]:
        s = r.get("scan", {})
        print(
            f"  {r['repo']:18} files={r['files_archived']:4} stripped={len(r['stripped'])} "
            f"rewrites={len(r['url_rewrites'])} block={s.get('block', '-')} review={s.get('review', '-')}",
            file=sys.stderr,
        )
    print(f"report: {args.out / 'export-report.md'}", file=sys.stderr)
    worst = max((r.get("scan", {}).get("block", 0) for r in report["repos"]), default=0)
    return 1 if worst else 0


if __name__ == "__main__":
    sys.exit(main())
