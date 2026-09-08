#!/usr/bin/env python3
"""bulk_prescan.py — split-layer Phase-1 driver: Layer 1 for the whole queue.

Clones each remaining worklist repo (blob-less), runs pqc_facts.py, writes
facts + CBOM to analysis-results/pqc/<slug>/, records a prescan marker, and
deletes the clone. Deterministic, resumable (skips slugs with existing
facts), parallel (worker pool). Layer-2 agent batches then score from the
facts files without cloning — the split roughly halves end-to-end sweep
time with byte-identical Layer-1 inputs.

Verified zero-hit repos (facts==[] with the coverage assertion) also get a
TEMPLATED not-applicable readiness report — a pure function of the
assertion, no interpretation involved (decision recorded in plan v1.3).

Usage:
  bulk_prescan.py --start 96 [--end N] [--workers 6] [--refresh]

--refresh (harness >= 0.132.2): re-scan repos whose existing facts carry
stale stamps (adapter_version or rules_sha256 differing from the current
adapter + rules pack). Facts already produced by the current pack are
still skipped, so a refresh sweep stays resumable and idempotent — rerun
the same command after any interruption.
"""

import argparse
import concurrent.futures as cf
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.context import add_config_home_arg, resolve_results_root
from traust.paths import HARNESS_ROOT

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
HERE = SKILL_DIR
VENV_PY = HARNESS_ROOT / ".venv" / "bin" / "python"


def sh(cmd, timeout, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def pick_slug(url: str, pqc: Path) -> str | None:
    m = re.match(r"https?://[^/]+/([^/]+)/([^/]+?)(\.git)?/?$", url)
    if not m:
        return None  # org-only / bare
    org, name = m.group(1).lower(), m.group(2).lower()
    # slug becomes an output directory under pqc/ — ".."/".git" etc.
    # would escape the tree (audit B3, plan P1.7)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name) or name in ("..",):
        return None
    slug = name
    d = pqc / slug
    if d.exists():
        # respect existing dir only if it is the SAME repository
        try:
            facts = next(d.glob("*-pqc-facts.json"))
            prev = json.loads(facts.read_text()).get("repository") or ""
            if prev.rstrip("/").lower() != url.rstrip("/").lower():
                slug = f"{org}--{name}"
        except (StopIteration, OSError, json.JSONDecodeError):
            pass
    return slug


def zero_hit_report(slug: str, url: str, commit: str, facts: dict) -> dict:
    def checks(ids):
        return [{"id": i, "result": "na", "rationale": "zero-hit: no crypto facts"} for i in ids]

    return {
        "title": f"PQC readiness — {slug} (verified zero-hit)",
        "metadata": {
            "repository": url,
            "commit": commit,
            "assessment_basis": "source",
            "facts_ref": f"{slug}-pqc-facts.json",
            "cbom_ref": f"{slug}-cbom.json",
            "tool": {
                k: facts["stamps"].get(k)
                for k in ("pqc_scan_commit", "rules_sha256", "binary_sha256", "adapter_version")
            },
        },
        # v0.162 readability contract (validate_readiness REQUIRED_READINESS)
        "summary": (
            "Verified zero-hit: the pinned scanner found no crypto "
            "usage in this repository, so PQC readiness is not "
            "applicable."
        ),
        "status": "not_applicable",
        "who_sets_tls": "unknown",
        "quantum_ready": "unknown",
        "why_not": [],
        "do_next": [],
        "capabilities": [],
        "scores": {
            "VULN": {
                "score": 100,
                "assessable_checks": 0,
                "checks": checks(["VULN-1", "VULN-2", "VULN-3", "VULN-4"]),
            },
            "AGIL": {
                "score": 100,
                "assessable_checks": 0,
                "checks": checks(["AGIL-1", "AGIL-2", "AGIL-3", "AGIL-4", "AGIL-5", "AGIL-6"]),
            },
            "PQCA": {
                "score": 100,
                "assessable_checks": 0,
                "checks": checks(["PQCA-1", "PQCA-2", "PQCA-3", "PQCA-4"]),
            },
            "HNDL": {
                "score": 100,
                "assessable_checks": 0,
                "checks": checks(["HNDL-1", "HNDL-2", "HNDL-3"]),
            },
            "overall": 100,
        },
        "flags": {
            "has_2030_clock_items": False,
            "hndl_priority": False,
            "runtime_verification_required": True,
        },
        "provenance_summary": {"counts": {}, "dominant": "none"},
        "clock_items": [],
        "readiness_bucket": "not-applicable",
        "notes": (
            "TEMPLATED zero-hit report (split-layer protocol): "
            + str(facts["coverage"].get("no_crypto_detected_assertion"))
        ),
    }


def current_stamps() -> dict:
    """The (adapter_version, rules hash) the current tree would stamp."""
    sys.path.insert(0, str(HERE))
    from pqc_facts import ADAPTER_VERSION, rules_pack_sha

    return {"adapter_version": ADAPTER_VERSION, "rules_sha256": rules_pack_sha(HERE / "rules")}


def _facts_stale(facts_path: Path, want: dict) -> bool:
    try:
        stamps = json.loads(facts_path.read_text()).get("stamps") or {}
    except (OSError, json.JSONDecodeError):
        return True  # unreadable facts are stale by definition
    return any(stamps.get(k) != v for k, v in want.items())


def one(entry: dict, pqc: Path, refresh_stamps: dict | None = None) -> dict:
    url = entry["repository"]
    slug = pick_slug(url, pqc)
    marker = {"repository": url, "tier": entry.get("tier")}
    if slug is None:
        return {
            **marker,
            "status": "unreachable",
            "error": "org-only or malformed URL",
            "slug": None,
        }
    marker["slug"] = slug
    outdir = pqc / slug
    existing = list(outdir.glob("*-pqc-facts.json"))
    if existing:
        if refresh_stamps is None:
            return {**marker, "status": "prescanned", "note": "already present"}
        if not any(_facts_stale(p, refresh_stamps) for p in existing):
            return {**marker, "status": "prescanned", "note": "already current-pack"}
    with tempfile.TemporaryDirectory(prefix=f"pqc-{slug[:24]}-") as td:
        clone = Path(td) / "repo"
        # depth-1 first: a scan needs one snapshot, and a shallow clone
        # transfers strictly less than blob:none (which still fetches the
        # full commit/tree graph and materializes all HEAD blobs at
        # checkout). blob:none stays as the fallback for servers that
        # reject shallow fetches.
        if not str(url).startswith("https://"):
            return {
                **marker,
                "status": "unreachable",
                "error": f"non-https url refused: {url[:80]}",
            }
        for _attempt, extra in enumerate((["--depth", "1"], ["--filter=blob:none"])):
            try:
                r = sh(["git", "clone", "-q", *extra, "--", url, str(clone)], 900)
            except subprocess.TimeoutExpired:
                return {**marker, "status": "unreachable", "error": "clone timeout"}
            if r.returncode == 0:
                break
        else:
            pass
        if not clone.exists():
            return {**marker, "status": "unreachable", "error": (r.stderr or "clone failed")[-160:]}
        commit = sh(["git", "-C", str(clone), "rev-parse", "HEAD"], 60).stdout.strip() or None
        outdir.mkdir(parents=True, exist_ok=True)
        facts_p = outdir / f"{slug}-pqc-facts.json"
        try:
            r = sh(
                [
                    str(VENV_PY),
                    str(HERE / "pqc_facts.py"),
                    "--repo-dir",
                    str(clone),
                    "--repo-url",
                    url,
                    "--out",
                    str(facts_p),
                    "--cbom-out",
                    str(outdir / f"{slug}-cbom.json"),
                ],
                2400,
            )
        except subprocess.TimeoutExpired:
            return {**marker, "status": "scan_timeout"}
        if r.returncode != 0 or not facts_p.exists():
            return {**marker, "status": "scan_failed", "error": (r.stderr or r.stdout)[-200:]}
        facts = json.loads(facts_p.read_text())
        n = len(facts.get("facts") or [])
        fp = sum(1 for f in facts.get("facts") or [] if f.get("path_class") == "first_party")
        res = {
            **marker,
            "status": "prescanned",
            "commit": commit,
            "facts": n,
            "first_party_facts": fp,
        }
        if (
            n == 0
            and facts["coverage"].get("no_crypto_detected_assertion")
            and (facts["coverage"].get("rules_in_pack") or 0) > 120
        ):
            rep = zero_hit_report(slug, url, commit, facts)
            rp = outdir / f"{slug}-pqc-readiness.json"
            rp.write_text(json.dumps(rep, indent=1) + "\n")
            v = sh([str(VENV_PY), str(HERE / "pqc_facts.py"), "--validate-readiness", str(rp)], 120)
            if v.returncode == 0:
                # scanner-derived text renders inside a code fence so
                # nothing in it can act as markdown/html (plan P3)
                (outdir / f"{slug}-pqc-readiness.md").write_text(
                    f"# PQC readiness — {slug}\n\nVerified zero-hit "
                    f"(templated, split-layer protocol): no crypto facts; "
                    f"bucket **not-applicable**.\n\n```\n"
                    f"{facts['coverage'].get('no_crypto_detected_assertion')}\n```\n"
                )
                res.update(
                    status="done",
                    overall=100,
                    readiness_bucket="not-applicable",
                    clock_items=0,
                    zero_hit=True,
                )
                (pqc / "_manifest" / "status" / f"{slug}.json").write_text(
                    json.dumps(res, indent=1)
                )
            else:
                rp.unlink()
        return res


def main():
    ap = argparse.ArgumentParser()
    add_config_home_arg(ap)
    ap.add_argument("--results-root", type=Path, default=None)
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, default=None)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="re-scan repos whose facts carry stale adapter/rules stamps (see module docstring)",
    )
    a = ap.parse_args()
    results = resolve_results_root(a)
    pqc = results / "pqc"
    state = json.loads((pqc / "_manifest" / "sweep-state.json").read_text())
    queue = state["queue"][a.start : a.end]
    pre = pqc / "_manifest" / "prescan"
    pre.mkdir(exist_ok=True)
    stamps = current_stamps() if a.refresh else None
    if stamps:
        print(
            f"[prescan] refresh mode: re-scanning facts not stamped "
            f"{stamps['adapter_version']}/"
            f"{stamps['rules_sha256'][:12]}",
            flush=True,
        )
    done = fail = 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for res in ex.map(lambda e: one(e, pqc, stamps), queue):
            slug = res.get("slug") or re.sub(r"\W+", "-", res["repository"])[-60:]
            (pre / f"{slug}.json").write_text(json.dumps(res, indent=1))
            if res["status"] in ("prescanned", "done"):
                done += 1
            else:
                fail += 1
                (pqc / "_manifest" / "status" / f"{slug}.json").write_text(
                    json.dumps(res, indent=1)
                )
            if (done + fail) % 25 == 0:
                print(f"[prescan] {done + fail}/{len(queue)} (ok={done} fail={fail})", flush=True)
    print(f"[prescan] COMPLETE: {done} ok, {fail} failed/unreachable of {len(queue)}")


if __name__ == "__main__":
    main()
