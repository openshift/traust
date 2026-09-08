#!/usr/bin/env python3
"""Sanitizer micro-probes (Phase B3 — the narrow, lab-free slice of D4).

Discovers repo-local sanitizer/validator functions and (on explicit
request) executes them in an isolated subprocess against curated bypass
corpora, recording per-payload transcripts. The measured motivation:
sanitizer-bypass findings are execution-shaped — reading `sanitize_jinja`
tells a reviewer little about whether `{{'{{'}}` survives it, and the
bt-awx-001 residual #3 is exactly such a miss (deep-fn-technique-plan
§1.3). Fourteen of the fuzz campaign's bugs were execution-only for the
same reason.

Two modes, deliberately separated:

  --list (DEFAULT)  pure-static discovery: candidate sanitizers by name/
                    signature shape, with file:line. Executes nothing.
  --run             EXECUTES REPOSITORY CODE. Imports each candidate's
                    module and calls it on bypass payloads. Run this only
                    inside the audit sandbox against a cloned, authorized
                    target — module import runs top-level code from the
                    audited repository (adversarial input by doctrine).
                    Containment: one `python3 -I` subprocess per module
                    (isolated mode — no user site, no PYTHONSTARTUP),
                    cleared environment, CPU/address-space rlimits,
                    hard timeout, cwd in a scratch dir.

Verdict vocabulary (soundness-gate aligned — an error is never evidence):
  survived      the payload's dangerous token reached the output intact
                → judged bypass CANDIDATE, never an auto-finding
  neutralized   output no longer carries the dangerous token
  error         the function (or its import) raised — outcome
                INCONCLUSIVE by the Phase-1 soundness rule: an
                error-signature transcript proves nothing about safety
  skipped       module import impossible (missing deps) — inconclusive

This is a CANDIDATE GENERATOR (docs/deterministic-inferential-mix.md):
`survived` still gets judged — the "sanitizer" may be defense-in-depth
behind a real encoder, or the probe's call convention may not match
production use. Judging protocol: secure-code-audit SKILL.md (sanitizer
micro-probe section).

Python-only in v1 (the acceptance target, awx sanitize_jinja, is Python;
Go/JS probing needs a build step — that is create-fuzzing territory).

Usage:
    python3 probe_sanitizers.py <repo-path> [--list | --run]
                                [--only NAME] [--out <file>]
                                [--timeout SECONDS]

Output defaults to <repo-basename>-sanitizer-probes.json in the CWD.
Exit 0 on completed discovery/probing; 1 on bad input.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from traust.paths import HARNESS_ROOT

SANITIZER_NAME_RX = re.compile(
    r"(?i)^_?(sanitize|sanitise|escape|clean|scrub|strip|filter|"
    r"validate|normalize|normalise|safe|quote|redact|mask)"
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
    "site-packages",
}
TEST_NAME_RX = re.compile(
    r"(^|[._-])(test|spec|mock|fixture|conftest)"
    r"s?([._-]|$)"
)
MAX_FILE_BYTES = 2 * 1024 * 1024

# Bypass corpora: (class, payload, survival token). A probe "survives"
# when the survival token appears in the function's output unchanged.
# Kept deliberately small and curated — this is a spot probe, not a
# fuzzer; breadth belongs to /create-fuzzing.
CORPORA = [
    ("ssti-jinja", "{{7*7}}", "{{"),
    ("ssti-jinja", "{%raw%}x{%endraw%}", "{%"),
    ("ssti-jinja", "{{''.__class__.__mro__}}", "__class__"),
    ("ssti-jinja-unicode", "｛｛7*7｝｝", "｛｛"),
    ("path-traversal", "../../etc/passwd", ".."),
    ("path-traversal-enc", "..%2f..%2fetc%2fpasswd", "..%2f"),
    ("path-traversal-win", "..\\..\\windows\\system32", "..\\"),
    ("null-byte", "safe.txt\x00.py", "\x00"),
    ("xss", "<script>alert(1)</script>", "<script"),
    ("xss-attr", '" onmouseover=alert(1) x="', "onmouseover="),
    ("sql", "' OR '1'='1", "' OR '"),
    ("shell", "; cat /etc/passwd #", "; cat"),
    ("shell-subst", "$(id)", "$("),
    ("crlf", "value\r\nSet-Cookie: pwn=1", "\r\n"),
    ("bidi", "file‮ gpj.exe", "‮"),
]


def _walk_py(repo: Path):
    for p in sorted(repo.rglob("*.py")):
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


def discover(repo: Path, only: str | None = None) -> list[dict]:
    """Static discovery of single-string-arg sanitizer-shaped functions."""
    out = []
    for f in _walk_py(repo):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if only:
                if node.name != only:
                    continue
            elif not SANITIZER_NAME_RX.match(node.name):
                continue
            args = node.args
            positional = args.args + args.posonlyargs
            # drop self/cls
            names = [a.arg for a in positional]
            if names and names[0] in ("self", "cls"):
                names = names[1:]
            required = len(names) - len(args.defaults)
            if not names or required > 1:
                continue  # probe convention: one required value argument
            out.append(
                {
                    "function": node.name,
                    "path": str(f.relative_to(repo)),
                    "line": node.lineno,
                    "arg": names[0],
                    "is_method": bool(positional and positional[0].arg in ("self", "cls")),
                }
            )
    return out


PROBE_DRIVER = r"""
import importlib.util, json, sys
mod_path, fn_name, payloads_json = sys.argv[1], sys.argv[2], sys.argv[3]
payloads = json.loads(payloads_json)
results = []
try:
    spec = importlib.util.spec_from_file_location("probe_target", mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, fn_name)
except BaseException as e:  # import failure = every probe inconclusive
    print(json.dumps({"import_error": f"{type(e).__name__}: {e}"[:300]}))
    sys.exit(0)
for p in payloads:
    try:
        out = fn(p["payload"])
        results.append({"class": p["class"],
                        "output": "" if out is None else str(out)[:500]})
    except BaseException as e:
        results.append({"class": p["class"],
                        "exception": f"{type(e).__name__}: {e}"[:300]})
print(json.dumps({"results": results}))
"""


def _rlimit_preexec():  # pragma: no cover - child-process context
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))


def probe(repo: Path, candidates: list[dict], timeout: int) -> list[dict]:
    """Execute candidates against the corpora. EXECUTES REPO CODE —
    caller is responsible for invoking this only in the audit sandbox."""
    probes = []
    payloads = [{"class": c, "payload": p} for c, p, _ in CORPORA]
    tokens = {(c, p): tok for c, p, tok in CORPORA}
    with tempfile.TemporaryDirectory(prefix="sanitizer-probe-") as scratch:
        for cand in candidates:
            if cand.get("is_method"):
                probes.append(
                    {
                        **cand,
                        "outcome": "skipped",
                        "reason": "bound method — no stable construction convention",
                    }
                )
                continue
            mod_path = str(repo / cand["path"])
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        PROBE_DRIVER,
                        mod_path,
                        cand["function"],
                        json.dumps(payloads),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=scratch,
                    env={"PATH": "/usr/bin:/bin"},
                    preexec_fn=_rlimit_preexec if os.name == "posix" else None,
                )
            except subprocess.TimeoutExpired:
                probes.append({**cand, "outcome": "error", "reason": f"timeout after {timeout}s"})
                continue
            line = (proc.stdout or "").strip().splitlines()
            data = None
            if line:
                with contextlib.suppress(json.JSONDecodeError):
                    data = json.loads(line[-1])
            if not data:
                probes.append(
                    {**cand, "outcome": "error", "reason": (proc.stderr or "no output")[:300]}
                )
                continue
            if "import_error" in data:
                probes.append({**cand, "outcome": "skipped", "reason": data["import_error"]})
                continue
            transcript = []
            survived = 0
            for p, r in zip(payloads, data.get("results", []), strict=False):
                entry = {"class": p["class"], "payload": p["payload"]}
                if "exception" in r:
                    entry["outcome"] = "error"
                    entry["exception"] = r["exception"]
                else:
                    tok = tokens[(p["class"], p["payload"])]
                    if tok in r.get("output", ""):
                        entry["outcome"] = "survived"
                        survived += 1
                    else:
                        entry["outcome"] = "neutralized"
                    entry["output_excerpt"] = r.get("output", "")[:200]
                transcript.append(entry)
            errors = sum(1 for t in transcript if t["outcome"] == "error")
            probes.append(
                {
                    **cand,
                    # soundness rule: a function that errored on every payload
                    # proved NOTHING — inconclusive, never "safe"
                    "outcome": (
                        "survived"
                        if survived
                        else "inconclusive"
                        if errors == len(transcript)
                        else "neutralized"
                    ),
                    "survived": survived,
                    "errors": errors,
                    "transcript": transcript,
                }
            )
    return probes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", type=Path)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--list",
        action="store_true",
        dest="list_only",
        help="discovery only (default): execute nothing",
    )
    mode.add_argument(
        "--run",
        action="store_true",
        help="EXECUTE repo sanitizers against the bypass corpora (audit-sandbox only)",
    )
    ap.add_argument("--only", help="probe a single function by name")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=20, help="per-module probe timeout, seconds")
    args = ap.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 1

    candidates = discover(repo, args.only)
    result = {
        "artifact": "sanitizer-probes",
        "repo": repo.name,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "mode": "run" if args.run else "list",
        "candidates": candidates,
    }
    if args.run:
        print(
            "probe_sanitizers: EXECUTING repository code in isolated "
            "subprocesses — audit-sandbox use only",
            file=sys.stderr,
        )
        result["probes"] = probe(repo, candidates, args.timeout)
        result["stats"] = {
            "candidates": len(candidates),
            "survived": sum(1 for p in result["probes"] if p["outcome"] == "survived"),
            "neutralized": sum(1 for p in result["probes"] if p["outcome"] == "neutralized"),
            "inconclusive": sum(
                1 for p in result["probes"] if p["outcome"] in ("inconclusive", "skipped", "error")
            ),
        }
    else:
        result["stats"] = {"candidates": len(candidates)}

    out = args.out or Path(f"{repo.name}-sanitizer-probes.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    s = result["stats"]
    extra = (
        f", {s['survived']} survived / {s['neutralized']} neutralized"
        f" / {s['inconclusive']} inconclusive"
        if args.run
        else ""
    )
    print(f"{result['repo']}: {s['candidates']} candidate sanitizer(s){extra} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
