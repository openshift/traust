#!/usr/bin/env python3
"""Config-matrix expander (deterministic effective-defaults pre-scan).

Enumerates the EFFECTIVE DEPLOYED DEFAULTS of a target checkout and emits
the matrix of (config key, effective default, consuming sink) triples as a
pre-scan artifact for model judging — deep-fn-technique-plan Phase B1 (D3).

The class this closes is COMPOSITIONAL: the insecure value is not written
anywhere greppable as a literal finding. It is assembled at deploy time
from a helm values chain, a compose environment block, a Kubernetes env
literal, or a code-side fallback (`os.Getenv("SSL_MODE")` falling back to
"disable"). Syntactic rules see each fragment and conclude nothing; this
expander materializes the composed default as a first-class enumerated
fact the model can judge (measured: config/DSN recall 0.25–0.50 after the
yaml rule pack alone — fn-analysis §4, leg-1 benchmark).

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md). Every security-relevant triple
still gets judged: the default may be dev-only, overridden by every
shipped overlay, or gated upstream. The judging protocol lives in
secure-code-audit SKILL.md (config-matrix pre-scan section).

Expansion tiers (v1 — ALL STATIC; no subprocess, no network, no template
execution):
  helm       values.yaml / values*.yaml defaults, flattened dotted keys;
             sink = {{ .Values.<key> }} usages in templates/ (file:line).
             Charts whose defaults only materialize under `helm template`
             rendering are recorded as a coverage_gap, never rendered —
             chart templates are adversarial input (harness doctrine) and
             v1 stays execution-free by design.
  kustomize  kustomization.yaml literals (configMapGenerator/
             secretGenerator literals, patch env inserts).
  compose    docker-compose*.yml / compose*.yml service environment maps.
  k8s        Deployment/StatefulSet/DaemonSet/CronJob env name/value
             literals and ConfigMap data entries in manifest YAML.
  env-chain  code-side fallback defaults:
               Go      os.Getenv(K) with `if x == "" { x = D }` or
                       `cmp.Or(os.Getenv(K), D)` shapes, viper.SetDefault
               Python  os.environ.get(K, D) / os.getenv(K, D)
               JS/TS   process.env.K || D / process.env.K ?? D
             sink = the consumption site itself.

Scope guard (plan D3 risk c): shipped defaults plus each SINGLE documented
override file — never the override cross-product. The measured misses are
all plain defaults.

Security-relevance classes (tls|dsn|auth|listener|debug|secret) get
`judgement_required: true`; everything else is emitted for completeness
with `judgement_required: false`. Unexpandable config systems found in the
tree (TOML/INI/properties, CRD-shaped operator config, render-gated helm)
are emitted as `coverage_gaps` — the audit's negative_results must name
them rather than silently claiming coverage.

Usage:
    python3 expand_config_matrix.py <repo-path> [--out <file>]
                                    [--max-triples N]

Output defaults to <repo-basename>-config-matrix.json in the CWD.
Exit 0 on a completed expansion (gaps included); 1 on bad input.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

from traust.paths import HARNESS_ROOT

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    yaml = None

# --------------------------------------------------------------------------
# security-relevance classification
# --------------------------------------------------------------------------

# Order matters: first matching class wins. Patterns run over
# "<key>=<value>" lowercased so composed facts (sslmode=disable) match even
# when neither fragment alone is alarming.
CLASS_PATTERNS = [
    (
        "dsn",
        re.compile(
            r"(sslmode|ssl_mode|dsn|database_url|db_url|connection_string|"
            r"jdbc:|postgres(ql)?://|mysql://|mongodb(\+srv)?://|redis://|"
            r"amqps?://)",
            re.I,
        ),
    ),
    (
        "tls",
        re.compile(
            r"(tls|ssl|https?_only|insecure|skip[_-]?verify|verify[_-]?"
            r"(peer|cert|hostname|ssl|tls)|ca[_-]?(file|cert|bundle)|"
            r"cert[_-]?file|key[_-]?file|cipher|min[_-]?version)",
            re.I,
        ),
    ),
    (
        "auth",
        re.compile(
            r"(auth|anonymous|no[_-]?login|allow[_-]?guest|rbac|"
            r"authoriz|authentic|oidc|oauth|token[_-]?(auth|required)|"
            r"api[_-]?key|basic[_-]?auth|require[_-]?(auth|login))",
            re.I,
        ),
    ),
    (
        "secret",
        re.compile(
            r"(password|passwd|secret|credential|private[_-]?key|"
            r"access[_-]?key|client[_-]?secret)",
            re.I,
        ),
    ),
    (
        "listener",
        re.compile(
            r"(listen|bind[_-]?(addr|address|host|ip)|0\.0\.0\.0|"
            r"host[_-]?(addr|address)?=|expose|public[_-]?(addr|url|port))",
            re.I,
        ),
    ),
    (
        "debug",
        re.compile(
            r"(debug|pprof|profil|trace[_-]?enabled|verbose|dev[_-]?mode|"
            r"development[_-]?mode|test[_-]?mode)",
            re.I,
        ),
    ),
]

# Values that make a security-relevant key IMMEDIATELY interesting; the
# judge sees every relevant triple either way, this only orders worklists.
WEAK_VALUE_RX = re.compile(
    r"^(disable[d]?|allow|prefer|false|0|off|none|noverify|insecure|"
    r"anonymous|guest|admin|changeme|password|0\.0\.0\.0(:\d+)?|\*|"
    r"http://.*)$",
    re.I,
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

MAX_FILE_BYTES = 2 * 1024 * 1024


def classify(key: str, value) -> tuple[str, bool]:
    probe = f"{key}={value}".lower()
    for cls, rx in CLASS_PATTERNS:
        if rx.search(probe):
            return cls, True
    return "other", False


def is_weak(value) -> bool:
    return bool(WEAK_VALUE_RX.match(str(value).strip()))


def _walk(repo: Path):
    for p in sorted(repo.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts):
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


def _rel(repo: Path, p: Path) -> str:
    return str(p.relative_to(repo))


def _load_yaml_docs(text: str):
    if yaml is None:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


def _flatten(prefix: str, node, out: dict):
    if isinstance(node, dict):
        for k, v in node.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(node, (str, int, float, bool)) or node is None:
        out[prefix] = node
    # lists: single documented defaults only — index-expanding lists is the
    # cross-product trap (plan D3 risk c); lists of scalars join for probe
    elif isinstance(node, list) and all(isinstance(i, (str, int, float, bool)) for i in node):
        out[prefix] = ",".join(str(i) for i in node)


def _line_of(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return None


def make_triple(key, value, system, path, line, sink=None):
    cls, relevant = classify(key, value)
    t = {
        "key": str(key),
        "effective_default": "" if value is None else str(value),
        "source": {"system": system, "path": path, "line": line},
        "sink": sink or {"status": "unresolved"},
        "class": cls,
        "judgement_required": relevant,
    }
    if relevant and is_weak(value):
        t["weak_default"] = True
    return t


# --------------------------------------------------------------------------
# tier: helm (static)
# --------------------------------------------------------------------------

HELM_VALUES_RX = re.compile(r"^values([.-].*)?\.ya?ml$")


def expand_helm(repo: Path, triples: list, gaps: list):
    charts = [
        p.parent
        for p in repo.rglob("Chart.yaml")
        if not any(part in SKIP_DIRS for part in p.relative_to(repo).parts)
    ]
    for chart_dir in charts:
        values_files = sorted(
            p for p in chart_dir.iterdir() if p.is_file() and HELM_VALUES_RX.match(p.name)
        )
        if not values_files:
            gaps.append(
                {
                    "system": "helm",
                    "path": _rel(repo, chart_dir),
                    "reason": "chart has no local values*.yaml — defaults "
                    "resolve only at render time (v1 never executes "
                    "helm template)",
                }
            )
            continue
        # sink index: .Values.<dotted key> usages across the chart templates
        usage: dict[str, dict] = {}
        tpl_dir = chart_dir / "templates"
        if tpl_dir.is_dir():
            for tpl in sorted(tpl_dir.rglob("*")):
                if not tpl.is_file() or tpl.suffix not in (".yaml", ".yml", ".tpl", ".txt"):
                    continue
                text = _read(tpl)
                for i, line in enumerate(text.splitlines(), 1):
                    for m in re.finditer(r"\.Values\.([A-Za-z0-9_.]+)", line):
                        usage.setdefault(
                            m.group(1),
                            {
                                "status": "template",
                                "path": _rel(repo, tpl),
                                "line": i,
                                "expr": line.strip()[:200],
                            },
                        )
        for vf in values_files:
            text = _read(vf)
            flat: dict = {}
            for doc in _load_yaml_docs(text):
                _flatten("", doc, flat)
            for key, value in flat.items():
                leaf = key.split(".")[-1]
                triples.append(
                    make_triple(
                        key,
                        value,
                        "helm",
                        _rel(repo, vf),
                        _line_of(text, leaf),
                        sink=usage.get(key),
                    )
                )


# --------------------------------------------------------------------------
# tier: kustomize (static literals)
# --------------------------------------------------------------------------


def expand_kustomize(repo: Path, triples: list, gaps: list):
    for kf in sorted(repo.rglob("kustomization.y*ml")):
        if any(part in SKIP_DIRS for part in kf.relative_to(repo).parts):
            continue
        text = _read(kf)
        for doc in _load_yaml_docs(text):
            for gen_key in ("configMapGenerator", "secretGenerator"):
                for gen in doc.get(gen_key) or []:
                    if not isinstance(gen, dict):
                        continue
                    for lit in gen.get("literals") or []:
                        if not isinstance(lit, str) or "=" not in lit:
                            continue
                        k, _, v = lit.partition("=")
                        triples.append(
                            make_triple(k, v, "kustomize", _rel(repo, kf), _line_of(text, lit))
                        )


# --------------------------------------------------------------------------
# tier: compose
# --------------------------------------------------------------------------

COMPOSE_RX = re.compile(r"^(docker-)?compose([.-].*)?\.ya?ml$")


def expand_compose(repo: Path, triples: list, gaps: list):
    for cf in _walk(repo):
        if not COMPOSE_RX.match(cf.name):
            continue
        text = _read(cf)
        for doc in _load_yaml_docs(text):
            for svc_name, svc in (doc.get("services") or {}).items():
                if not isinstance(svc, dict):
                    continue
                env = svc.get("environment")
                items = []
                if isinstance(env, dict):
                    items = list(env.items())
                elif isinstance(env, list):
                    items = [e.partition("=")[::2] for e in env if isinstance(e, str) and "=" in e]
                for k, v in items:
                    triples.append(
                        make_triple(
                            k,
                            v,
                            "compose",
                            _rel(repo, cf),
                            _line_of(text, str(k)),
                            sink={"status": "service", "service": str(svc_name)},
                        )
                    )


# --------------------------------------------------------------------------
# tier: k8s manifests (env literals + ConfigMap data)
# --------------------------------------------------------------------------

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod"}


def expand_k8s(repo: Path, triples: list, gaps: list):
    for mf in _walk(repo):
        if mf.suffix not in (".yaml", ".yml"):
            continue
        if COMPOSE_RX.match(mf.name) or HELM_VALUES_RX.match(mf.name):
            continue
        rel_parts = mf.relative_to(repo).parts
        if "templates" in rel_parts:  # helm templates handled by helm tier
            continue
        text = _read(mf)
        if "kind:" not in text:
            continue
        for doc in _load_yaml_docs(text):
            kind = doc.get("kind")
            if kind == "ConfigMap":
                for k, v in (doc.get("data") or {}).items():
                    if isinstance(v, str) and len(v) > 300:
                        continue  # embedded file bodies judged elsewhere
                    triples.append(
                        make_triple(k, v, "k8s-configmap", _rel(repo, mf), _line_of(text, str(k)))
                    )
            elif kind in WORKLOAD_KINDS:
                spec = doc.get("spec") or {}
                tpl = (
                    (spec.get("jobTemplate") or {}).get("spec", {}).get("template")
                    or spec.get("template")
                    or {}
                )
                pod = tpl.get("spec") or {}
                for ctr in (pod.get("containers") or []) + (pod.get("initContainers") or []):
                    if not isinstance(ctr, dict):
                        continue
                    for env in ctr.get("env") or []:
                        if not isinstance(env, dict) or "value" not in env:
                            continue
                        triples.append(
                            make_triple(
                                env.get("name"),
                                env.get("value"),
                                "k8s-env",
                                _rel(repo, mf),
                                _line_of(text, str(env.get("name"))),
                                sink={"status": "container", "container": ctr.get("name")},
                            )
                        )


# --------------------------------------------------------------------------
# tier: env-chain (code-side fallback defaults)
# --------------------------------------------------------------------------

GO_GETENV_IF_RX = re.compile(
    r'(?P<var>\w+)\s*:?=\s*os\.(?:Getenv|LookupEnv)\(\s*"(?P<key>[^"]+)"'
    r"\s*\)"
)
GO_IF_EMPTY_RX_TPL = r'if\s+{var}\s*==\s*""\s*\{{\s*{var}\s*=\s*"(?P<default>[^"]*)"'
GO_CMP_OR_RX = re.compile(
    r'cmp\.Or\(\s*os\.Getenv\(\s*"(?P<key>[^"]+)"\s*\)\s*,\s*'
    r'"(?P<default>[^"]*)"\s*\)'
)
GO_VIPER_RX = re.compile(
    r'viper\.SetDefault\(\s*"(?P<key>[^"]+)"\s*,\s*'
    r'(?P<default>"[^"]*"|true|false|[\d.]+)\s*\)'
)
PY_GET_RX = re.compile(
    r'os\.(?:environ\.get|getenv)\(\s*["\'](?P<key>[^"\']+)["\']\s*,\s*'
    r'(?P<default>"[^"]*"|\'[^\']*\'|True|False|None|[\d.]+)\s*\)'
)
JS_RX = re.compile(
    r"process\.env\.(?P<key>\w+)\s*(?:\|\||\?\?)\s*"
    r'(?P<default>"[^"]*"|\'[^\']*\'|`[^`]*`|true|false|[\d.]+)'
)

CODE_SUFFIXES = {
    ".go": "go",
    ".py": "python",
    ".js": "js",
    ".ts": "js",
    ".mjs": "js",
    ".jsx": "js",
    ".tsx": "js",
}


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'`" and s[-1] == s[0]:
        return s[1:-1]
    return s


def expand_env_chain(repo: Path, triples: list, gaps: list):
    for cf in _walk(repo):
        lang = CODE_SUFFIXES.get(cf.suffix)
        if not lang:
            continue
        name = cf.name.lower()
        if lang == "go" and name.endswith("_test.go"):
            continue
        if re.search(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)", name):
            continue
        text = _read(cf)
        rel = _rel(repo, cf)
        lines = text.splitlines()

        def add(key, default, line_no, expr, _lang=lang, _rel=rel):
            triples.append(
                make_triple(
                    key,
                    default,
                    f"env-chain-{_lang}",
                    _rel,
                    line_no,
                    sink={
                        "status": "code",
                        "path": _rel,
                        "line": line_no,
                        "expr": expr.strip()[:200],
                    },
                )
            )

        if lang == "go":
            for m in GO_CMP_OR_RX.finditer(text):
                ln = text[: m.start()].count("\n") + 1
                add(m.group("key"), m.group("default"), ln, m.group(0))
            for m in GO_VIPER_RX.finditer(text):
                ln = text[: m.start()].count("\n") + 1
                add(m.group("key"), _strip_quotes(m.group("default")), ln, m.group(0))
            for m in GO_GETENV_IF_RX.finditer(text):
                var, key = m.group("var"), m.group("key")
                ln = text[: m.start()].count("\n") + 1
                window = "\n".join(lines[ln - 1 : ln + 8])
                m2 = re.search(GO_IF_EMPTY_RX_TPL.format(var=re.escape(var)), window)
                if m2:
                    add(
                        key,
                        m2.group("default"),
                        ln,
                        f'{var} := os.Getenv("{key}") // fallback "{m2.group("default")}"',
                    )
        elif lang == "python":
            for m in PY_GET_RX.finditer(text):
                default = m.group("default")
                if default in ("None",):
                    continue
                ln = text[: m.start()].count("\n") + 1
                add(m.group("key"), _strip_quotes(default), ln, m.group(0))
        else:  # js/ts
            for m in JS_RX.finditer(text):
                ln = text[: m.start()].count("\n") + 1
                add(m.group("key"), _strip_quotes(m.group("default")), ln, m.group(0))


# --------------------------------------------------------------------------
# coverage-gap detection for systems v1 does not expand
# --------------------------------------------------------------------------

UNEXPANDED = [
    (
        re.compile(r"\.(toml|ini|properties|conf|cfg)$"),
        "toml/ini/properties config file — no v1 expander",
    ),
]


def detect_gaps(repo: Path, gaps: list, seen_limit: int = 20):
    seen: dict[str, list] = {}
    for p in _walk(repo):
        for rx, reason in UNEXPANDED:
            if rx.search(p.name):
                seen.setdefault(reason, []).append(_rel(repo, p))
    for reason, paths in seen.items():
        gaps.append(
            {
                "system": "config-file",
                "reason": reason,
                "paths": paths[:seen_limit],
                "count": len(paths),
            }
        )
    # CRD-shaped operator config: defaults live in the operator, not the tree
    crds = [
        _rel(repo, p)
        for p in repo.rglob("*.yaml")
        if "crd" in p.name.lower()
        and not any(part in SKIP_DIRS for part in p.relative_to(repo).parts)
    ]
    if crds:
        gaps.append(
            {
                "system": "crd",
                "reason": "CRD-shaped config — effective defaults are "
                "operator-applied, not derivable from the tree",
                "paths": crds[:seen_limit],
                "count": len(crds),
            }
        )


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def expand(repo: Path, max_triples: int) -> dict:
    triples: list[dict] = []
    gaps: list[dict] = []
    expand_helm(repo, triples, gaps)
    expand_kustomize(repo, triples, gaps)
    expand_compose(repo, triples, gaps)
    expand_k8s(repo, triples, gaps)
    expand_env_chain(repo, triples, gaps)
    detect_gaps(repo, gaps)

    # dedupe on (key, default, source path, line)
    seen = set()
    unique = []
    for t in triples:
        sig = (t["key"], t["effective_default"], t["source"]["path"], t["source"]["line"])
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(t)

    # judged worklist first (weak defaults up front), then the rest
    unique.sort(
        key=lambda t: (
            not t["judgement_required"],
            not t.get("weak_default", False),
            t["class"],
            t["key"],
        )
    )
    truncated = max(0, len(unique) - max_triples)
    if truncated:
        gaps.append(
            {
                "system": "expander",
                "reason": f"triple cap {max_triples} reached — "
                f"{truncated} lowest-priority triples "
                f"dropped (judged classes kept first)",
                "count": truncated,
            }
        )
        unique = unique[:max_triples]

    by_class: dict[str, int] = {}
    for t in unique:
        by_class[t["class"]] = by_class.get(t["class"], 0) + 1
    return {
        "artifact": "config-matrix",
        "repo": repo.name,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "harness_version": (HARNESS_ROOT / "VERSION").read_text().strip()
        if (HARNESS_ROOT / "VERSION").is_file()
        else "unknown",
        "yaml_parser": "available" if yaml else "MISSING — yaml tiers skipped, env-chain only",
        "triples": unique,
        "coverage_gaps": gaps,
        "stats": {
            "total": len(unique),
            "judgement_required": sum(1 for t in unique if t["judgement_required"]),
            "weak_defaults": sum(1 for t in unique if t.get("weak_default")),
            "by_class": by_class,
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("repo", type=Path, help="local checkout to expand")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--max-triples", type=int, default=2000)
    args = ap.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 1
    if yaml is None:
        print(
            "warning: PyYAML unavailable — yaml tiers skipped, env-chain tier only", file=sys.stderr
        )

    result = expand(repo, args.max_triples)
    out = args.out or Path(f"{repo.name}-config-matrix.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    s = result["stats"]
    print(
        f"{result['repo']}: {s['total']} triples "
        f"({s['judgement_required']} to judge, "
        f"{s['weak_defaults']} weak defaults), "
        f"{len(result['coverage_gaps'])} coverage gaps -> {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
