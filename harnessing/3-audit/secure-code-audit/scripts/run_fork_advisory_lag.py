#!/usr/bin/env python3
"""Fork advisory-lag candidates (deterministic fork pre-scan stage).

Detects whether a pinned target clone is a FORK (or wholesale vendored
copy) of an upstream project, resolves which upstream version the fork
tracks, and queries OSV for advisories whose affected range CONTAINS
that tracked version. An in-range advisory on a fork means the fork
ships the vulnerable upstream code unless it independently backported
the fix — the dominant miss pattern measured in the CVE-replay backfill
(>=21 of 51 missed CVEs sat in pinned forks: CoreDNS forks 15,
oauth2-proxy 4, prometheus 2, envoy) because audits of pinned forks
never diffed the fork point against upstream advisory ranges.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). Every in-range advisory still
gets judged: the fork may carry the backport. Unlike dependency
candidates, however, these sit in the repository's OWN shipped code —
first-party supply-chain material, not `dependency_audit` context.

Stage 1 (pure-local, deterministic): fork detection via, in order,
(a) go.mod module path vs the clone's actual remote/directory identity,
plus replace directives pointing at fork orgs; (b) VERSION /
version.go / CoreVersion-style constants naming the tracked upstream
release; (c) git remotes pointing at a different org (fork + upstream
remote layout); (d) vendored-upstream layout (vendor/ or third_party/
carrying a whole project with its own go.mod/package.json). Every
signal is recorded with file:line evidence.

Stage 2 (network, skipped under --offline): each detected upstream
identity+version is queried against https://api.osv.dev/v1/query; only
advisories whose affected range contains the tracked version are kept.
Network failure is tolerated: stage-1 output is still emitted with
"network": "error: <reason>" and exit 0.

Usage:
    python3 run_fork_advisory_lag.py --repo <clone> [--out <file>]
                                     [--offline] [--timeout SECONDS]
                                     [--osv-url URL]

Output defaults to <repo-basename>-fork-advisory-lag.json in the CWD.
Exit 0 on a completed scan (fork or not, network or not); 1 on bad input.
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from traust.paths import HARNESS_ROOT
from traust.registry.osv_urls import osv_query_url

OSV_QUERY_URL = osv_query_url()

# vanity import prefixes -> canonical code-host identity, so that e.g.
# k8s.io/kubernetes checked out from github.com/kubernetes/kubernetes is
# NOT misread as a fork
VANITY_PREFIXES = {
    "k8s.io/": "github.com/kubernetes/",
    "sigs.k8s.io/": "github.com/kubernetes-sigs/",
    "golang.org/x/": "github.com/golang/",
    "go.etcd.io/": "github.com/etcd-io/",
    "go.uber.org/": "github.com/uber-go/",
    "google.golang.org/grpc": "github.com/grpc/grpc-go",
    "google.golang.org/protobuf": "github.com/protobuf/protobuf-go",
}

# version-constant names that never name the tracked upstream release
_VERSION_NAME_SKIP = {
    "goversion",
    "apiversion",
    "schemaversion",
    "schemeversion",
    "protocolversion",
    "minversion",
    "maxversion",
    "tlsversion",
}
_VERSION_CONST_RE = re.compile(
    r"^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)\s*"
    r'(?::?=|\s+string\s*=)\s*"v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)"'
)
_SEMVERISH_RE = re.compile(r"^v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*$")
# directories never descended into during version/vendor walks
_WALK_SKIP = {".git", "node_modules", ".venv", "__pycache__", "testdata"}
# parent-directory names that are checkout containers, not fork orgs —
# suppresses the directory-identity fallback for plain upstream clones
_CONTAINER_DIRS = {
    "tmp",
    "temp",
    "src",
    "repos",
    "clones",
    "checkouts",
    "work",
    "builds",
    "go",
    "github.com",
    "gitlab.com",
}


def harness_version():
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return None
    try:
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (subprocess.SubprocessError, OSError):
        return v


def repo_head(repo):
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


# --------------------------------------------------------------- identity


def parse_remote_url(url: str):
    """git remote URL -> (host, org, name) or None."""
    url = url.strip()
    m = re.match(
        r"(?:ssh://)?(?:[\w.-]+@)?([\w.-]+)[:/]([^/\s]+)/(\S+)", re.sub(r"^https?://", "", url)
    )
    if not m:
        return None
    host, org, name = m.groups()
    name = re.sub(r"\.git$", "", name.rstrip("/"))
    return host.lower(), org, name


def module_identity(module: str):
    """Go module path -> canonical (host, org, name) or None.

    Applies the vanity-prefix table first so vanity import paths compare
    equal to their code-host checkout identity.
    """
    for prefix, canonical in VANITY_PREFIXES.items():
        if module == prefix.rstrip("/") or module.startswith(prefix):
            module = canonical + module[len(prefix) :] if prefix.endswith("/") else canonical
            break
    parts = module.split("/")
    if len(parts) < 3 or "." not in parts[0]:
        return None
    return parts[0].lower(), parts[1], parts[2]


def _evidence(repo: Path, path: Path, line_no: int, quote: str) -> dict:
    try:
        rel = str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        rel = str(path)
    return {"file": rel, "line": line_no, "quote": quote.strip()[:200]}


def _origin_identity(repo: Path):
    try:
        url = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return parse_remote_url(url) if url else None


def _gomod_requires(text: str) -> dict:
    """All `module version` pairs (require stanzas) in a go.mod text."""
    out = {}
    for m in re.finditer(r"^\s*([A-Za-z0-9._/\-~]+)\s+(v\d\S*)\s*(?://.*)?$", text, re.MULTILINE):
        out.setdefault(m.group(1), m.group(2))
    return out


# --------------------------------------------------------- stage 1: detect


def detect_gomod_fork(repo: Path) -> list[dict]:
    """(a) go.mod module path vs actual identity + replace directives."""
    signals = []
    gomod = repo / "go.mod"
    if not gomod.is_file():
        return signals
    text = gomod.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    mod_line_no, module = None, None
    for i, line in enumerate(lines, 1):
        m = re.match(r"^module\s+(\S+)", line)
        if m:
            mod_line_no, module = i, m.group(1)
            break

    if module:
        mod_id = module_identity(module)
        actual = _origin_identity(repo)
        if (
            mod_id
            and actual
            and (mod_id[1].lower(), mod_id[2].lower()) != (actual[1].lower(), actual[2].lower())
        ):
            signals.append(
                {
                    "type": "go-mod-module-path",
                    "identity": "/".join(mod_id),
                    "osv_package": module,
                    "ecosystem": "Go",
                    "scope": "",
                    "evidence": [_evidence(repo, gomod, mod_line_no, lines[mod_line_no - 1])],
                    "detail": f"module declares upstream identity but checkout "
                    f"is {actual[0]}/{actual[1]}/{actual[2]}",
                }
            )
        elif mod_id and not actual:
            # directory-identity fallback: <org>/<name> trailing path
            parent = repo.resolve().parent.name
            if (
                repo.name.lower() == mod_id[2].lower()
                and parent
                and not parent.startswith(".")
                and parent.lower() not in _CONTAINER_DIRS
                and parent.lower() != mod_id[1].lower()
            ):
                signals.append(
                    {
                        "type": "go-mod-module-path",
                        "identity": "/".join(mod_id),
                        "osv_package": module,
                        "ecosystem": "Go",
                        "scope": "",
                        "evidence": [_evidence(repo, gomod, mod_line_no, lines[mod_line_no - 1])],
                        "detail": f"module declares upstream identity but "
                        f"checkout directory is {parent}/{repo.name}",
                    }
                )

    # replace directives pointing at a different org = pinned fork of dep
    requires = _gomod_requires(text)
    in_block = False
    for i, line in enumerate(lines, 1):
        stripped = line.split("//")[0].strip()
        if re.match(r"^replace\s*\($", stripped):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        body = None
        if in_block and "=>" in stripped:
            body = stripped
        else:
            m = re.match(r"^replace\s+(.*)$", stripped)
            if m and "=>" in m.group(1):
                body = m.group(1)
        if not body:
            continue
        m = re.match(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$", body)
        if not m:
            continue
        old, _old_ver, new, new_ver = m.groups()
        if new.startswith(".") or new.startswith("/"):
            continue  # local-path replace — no fork identity to compare
        old_id, new_id = module_identity(old), module_identity(new)
        if not old_id or not new_id or old_id == new_id:
            continue
        version = new_ver or requires.get(old)
        signals.append(
            {
                "type": "go-mod-replace",
                "identity": "/".join(old_id),
                "osv_package": old,
                "ecosystem": "Go",
                "scope": "",
                "version": version.lstrip("v") if version else None,
                "evidence": [_evidence(repo, gomod, i, line)],
                "detail": f"replace routes {old} to fork {new}",
            }
        )
    return signals


def detect_version_constants(repo: Path, base: Path | None = None) -> list[dict]:
    """(b) VERSION files / version.go X.Y.Z constants under base (or root).

    Version signals carry no upstream identity on their own — they resolve
    the tracked version for identities found by (a)/(c)/(d).
    """
    base = base or repo
    signals = []
    base_depth = len(base.resolve().parts)
    for root, dirs, files in os.walk(base):
        rootp = Path(root)
        depth = len(rootp.resolve().parts) - base_depth
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _WALK_SKIP and d not in ("vendor", "third_party") and depth < 4
        )
        for fname in sorted(files):
            path = rootp / fname
            if fname.lower() in ("version", "version.txt"):
                try:
                    first = path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                except OSError:
                    continue
                if first and _SEMVERISH_RE.match(first[0].strip()):
                    signals.append(
                        {
                            "type": "version-constant",
                            "version": first[0].strip().lstrip("v"),
                            "scope": "" if base == repo else str(base.relative_to(repo)),
                            "evidence": [_evidence(repo, path, 1, first[0])],
                        }
                    )
            elif fname.lower() == "version.go":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    m = _VERSION_CONST_RE.match(line)
                    if not m:
                        continue
                    name = m.group(1).lower()
                    if not name.endswith("version") or name in _VERSION_NAME_SKIP:
                        continue
                    signals.append(
                        {
                            "type": "version-constant",
                            "version": m.group(2),
                            "scope": "" if base == repo else str(base.relative_to(repo)),
                            "evidence": [_evidence(repo, path, i, line)],
                        }
                    )
    return signals


def detect_git_remotes(repo: Path) -> list[dict]:
    """(c) a non-origin remote pointing at a different org (fork layout)."""
    signals = []
    cfg = repo / ".git" / "config"
    if (repo / ".git").is_file():  # worktree: .git is a gitdir file
        try:
            gitdir = (repo / ".git").read_text().split("gitdir:")[1].strip()
            cfg = (repo / gitdir).resolve() / "config"
        except (OSError, IndexError):
            return signals
    if not cfg.is_file():
        return signals
    try:
        lines = cfg.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return signals
    origin = _origin_identity(repo)
    remote = None
    for i, line in enumerate(lines, 1):
        m = re.match(r'^\[remote "([^"]+)"\]', line.strip())
        if m:
            remote = m.group(1)
            continue
        m = re.match(r"^\s*url\s*=\s*(\S+)", line)
        if not m or remote in (None, "origin"):
            continue
        ident = parse_remote_url(m.group(1))
        if not ident or not origin:
            continue
        if (ident[1].lower(), ident[2].lower()) != (origin[1].lower(), origin[2].lower()):
            signals.append(
                {
                    "type": "git-remote",
                    "identity": "/".join(ident),
                    "osv_package": None,
                    "ecosystem": None,
                    "scope": "",
                    "evidence": [_evidence(repo, cfg, i, line)],
                    "detail": f'remote "{remote}" points at a different org '
                    f"than origin ({'/'.join(origin)})",
                }
            )
    return signals


def detect_vendored_projects(repo: Path) -> list[dict]:
    """(d) vendor/ or third_party/ carrying a whole project of its own."""
    signals = []
    for holder in ("vendor", "third_party"):
        base = repo / holder
        if not base.is_dir():
            continue
        base_depth = len(base.resolve().parts)
        for root, dirs, files in os.walk(base):
            rootp = Path(root)
            depth = len(rootp.resolve().parts) - base_depth
            dirs[:] = sorted(d for d in dirs if d not in _WALK_SKIP and depth < 4)
            hit = None
            if "go.mod" in files:
                gomod = rootp / "go.mod"
                text = gomod.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(text.splitlines(), 1):
                    m = re.match(r"^module\s+(\S+)", line)
                    if m:
                        hit = {
                            "identity": m.group(1),
                            "osv_package": m.group(1),
                            "ecosystem": "Go",
                            "evidence": [_evidence(repo, gomod, i, line)],
                            "version": None,
                        }
                        break
            elif "package.json" in files:
                pj = rootp / "package.json"
                try:
                    doc = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
                except (OSError, json.JSONDecodeError):
                    doc = {}
                if isinstance(doc, dict) and doc.get("name"):
                    hit = {
                        "identity": doc["name"],
                        "osv_package": doc["name"],
                        "ecosystem": "npm",
                        "evidence": [
                            _evidence(
                                repo,
                                pj,
                                1,
                                f'"name": "{doc["name"]}", "version": "{doc.get("version", "")}"',
                            )
                        ],
                        "version": (doc.get("version") or "").lstrip("v") or None,
                    }
            if hit:
                scope = str(rootp.relative_to(repo))
                signals.append(
                    {
                        "type": "vendored-project",
                        "scope": scope,
                        "detail": f"whole project vendored under {holder}/",
                        **hit,
                    }
                )
                dirs[:] = []  # a project root — do not descend further
    return signals


def stage1_detect(repo: Path):
    """Run all detectors; return (signals, upstreams)."""
    signals = []
    signals += detect_gomod_fork(repo)
    signals += detect_git_remotes(repo)
    signals += detect_vendored_projects(repo)

    identity_signals = [s for s in signals if s.get("identity")]
    if not identity_signals:
        return signals, []
    # version constants only matter once an identity signal exists
    version_signals = detect_version_constants(repo)
    for s in signals:
        if s["type"] == "vendored-project" and not s.get("version"):
            inner = detect_version_constants(repo, repo / s["scope"])
            if inner:
                s["version"] = inner[0]["version"]
                s["evidence"] = s["evidence"] + inner[0]["evidence"]
                version_signals += inner
    signals += version_signals

    # OSV package name for remote-derived identities: prefer the root
    # go.mod module path (the fork keeps upstream's module identity)
    root_module = None
    gomod = repo / "go.mod"
    if gomod.is_file():
        m = re.search(
            r"^module\s+(\S+)", gomod.read_text(encoding="utf-8", errors="replace"), re.MULTILINE
        )
        root_module = m.group(1) if m else None

    upstreams: dict[str, dict] = {}
    for s in identity_signals:
        pkg = s.get("osv_package")
        eco = s.get("ecosystem")
        if not pkg and s["scope"] == "":
            pkg, eco = root_module, "Go" if root_module else None
        key = (pkg or s["identity"]).lower()
        up = upstreams.setdefault(
            key,
            {
                "identity": s["identity"],
                "osv_package": pkg or s["identity"],
                "ecosystem": eco or "Go",
                "tracked_version": s.get("version"),
                "scope": s["scope"],
                "evidence": [],
                "advisories": [],
            },
        )
        if not up["tracked_version"] and s.get("version"):
            up["tracked_version"] = s["version"]
        for ev in s["evidence"]:
            if ev not in up["evidence"]:
                up["evidence"].append(ev)

    # resolve tracked versions from version-constant signals, scope-matched
    for up in upstreams.values():
        if up["tracked_version"]:
            continue
        scoped = [v for v in version_signals if v["scope"] == up["scope"]]
        scoped.sort(key=lambda v: (v["evidence"][0]["file"].count("/"), v["evidence"][0]["file"]))
        if scoped:
            up["tracked_version"] = scoped[0]["version"]
            up["evidence"].extend(e for e in scoped[0]["evidence"] if e not in up["evidence"])
    return signals, list(upstreams.values())


# ------------------------------------------------------- stage 2: OSV query


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fixed_version(vuln: dict, pkg_name: str):
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") and p["name"].lower() != pkg_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def _affected_ranges(vuln: dict, pkg_name: str) -> list[dict]:
    out = []
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") and p["name"].lower() != pkg_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            out.append({"type": rng.get("type"), "events": rng.get("events") or []})
    return out


def advisory_record(vuln: dict, pkg_name: str) -> dict:
    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases") or [],
        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200]),
        "affected_ranges": _affected_ranges(vuln, pkg_name),
        "fixed_version": _fixed_version(vuln, pkg_name),
        # the OSV /v1/query version parameter already filters to
        # advisories whose affected range contains tracked_version
        "in_range": True,
    }


def stage2_advisories(upstreams: list[dict], url: str, timeout: int) -> str:
    """Query OSV per upstream; returns the network status string."""
    for up in upstreams:
        if not up["tracked_version"]:
            continue  # nothing to range-match — stage-1 output only
        payload = {
            "version": up["tracked_version"],
            "package": {"name": up["osv_package"], "ecosystem": up["ecosystem"]},
        }
        try:
            vulns, page_token, pages = [], None, 0
            while pages < 5:
                body = dict(payload)
                if page_token:
                    body["page_token"] = page_token
                resp = _post_json(url, body, timeout)
                vulns += resp.get("vulns") or []
                page_token = resp.get("next_page_token")
                pages += 1
                if not page_token:
                    break
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            OSError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            return f"error: {exc}"
        up["advisories"] = [advisory_record(v, up["osv_package"]) for v in vulns if v.get("id")]
    return "ok"


# ------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="target repo clone at the pinned audit SHA (read-only)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output JSON (default: ./<repo-basename>-fork-advisory-lag.json)",
    )
    ap.add_argument("--offline", action="store_true", help="stage 1 only — never touch the network")
    ap.add_argument(
        "--timeout", type=int, default=30, help="per-request OSV API timeout in seconds"
    )
    ap.add_argument(
        "--osv-url", default=OSV_QUERY_URL, help="OSV query endpoint (default: api.osv.dev)"
    )
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"ERROR: {repo} is not a directory", file=sys.stderr)
        return 1
    out = args.out or Path.cwd() / f"{repo.name}-fork-advisory-lag.json"

    signals, upstreams = stage1_detect(repo)
    fork_detected = bool(upstreams)

    if not fork_detected or args.offline:
        network = "skipped"
    else:
        network = stage2_advisories(upstreams, args.osv_url, args.timeout)

    for up in upstreams:
        up.pop("scope", None)
        up.pop("osv_package", None)

    doc = {
        "artifact": "fork-advisory-lag-candidates",
        "role": (
            "candidate generator — context for audit/triage agents; "
            "never a finding or verdict of record. An in-range "
            "advisory on a fork is a first-class finding CANDIDATE "
            "in the fork's own shipped code — judge each one: the "
            "fork may have backported the fix."
        ),
        "fork_detected": fork_detected,
        "signals": signals,
        "upstreams": upstreams,
        "network": network,
        "tool_version": harness_version(),
        "repository": str(repo),
        "commit": repo_head(repo),
        "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    if not fork_detected:
        print("  no fork signals — not a fork/vendored-upstream checkout")
    else:
        for up in upstreams:
            print(
                f"  fork of {up['identity']} @ "
                f"{up['tracked_version'] or '(version unresolved)'}: "
                f"{len(up['advisories'])} in-range advisories "
                f"(network: {network})"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
