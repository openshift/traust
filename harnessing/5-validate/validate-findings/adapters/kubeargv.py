"""Parse kubectl/oc command text into the facts the safety layer needs.

Born from prior assessment F1/F2 (both
execution-confirmed): classification keyed on the harness verb let every
kube PoC ride the `raw` SAFE_VERBS entry, and scope was enforced on the
parsed target dict while the command's REAL argv carried `-A`,
`--kubeconfig`, extra `-n` flags, and credential overrides the guard
never saw. This module reads the command the way the tool will.

Facts only — callers decide. `classify_worst()` is a severity ceiling
for AdapterBase.classify; `analyze()` feeds execute-time scope checks.
"""

from __future__ import annotations

import dataclasses
import shlex

KUBE_BINARIES = ("kubectl", "oc")

# Flags that retarget the command at a different cluster/identity than
# the engagement pinned, or disable transport security. Never legitimate
# in PoC-derived step text (the adapter supplies context/kubeconfig).
DENIED_FLAGS = (
    "--kubeconfig",
    "--context",
    "--cluster",
    "--user",
    "--server",
    "-s",
    "--token",
    "--as",
    "--as-group",
    "--as-uid",
    "--insecure-skip-tls-verify",
    "--tls-server-name",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--username",
    "--password",
)

DESTRUCTIVE_SUBCOMMANDS = frozenset(
    {
        "delete",
        "drain",
        "taint",
        "cordon",
        "uncordon",
        "evict",
        "replace",
    }
)
MUTATING_SUBCOMMANDS = frozenset(
    {
        "apply",
        "create",
        "patch",
        "edit",
        "set",
        "label",
        "annotate",
        "scale",
        "rollout",
        "expose",
        "autoscale",
        "run",
        "exec",
        "rsh",
        "debug",
        "cp",
        "attach",
        "port-forward",
        "adm",
        "policy",
        "cordon",
        "certificate",
        "kustomize",
    }
)
SAFE_SUBCOMMANDS = frozenset(
    {
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "version",
        "api-resources",
        "api-versions",
        "whoami",
        "cluster-info",
        "wait",
        "diff",
        "status",
        "can-i",
    }
)

_SEVERITY = {"safe": 0, "mutating": 1, "destructive": 2}


@dataclasses.dataclass
class KubeCmd:
    subcommand: str | None = None
    namespaces: tuple = ()  # every -n/--namespace value seen
    all_namespaces: bool = False  # -A / --all-namespaces
    resource: str | None = None  # first resource-ish token after subcmd
    denied_flags: tuple = ()  # DENIED_FLAGS present in the argv
    classification: str = "safe"


def _classify_subcommand(sub: str | None, argv: list) -> str:
    if sub is None:
        return "safe"
    if sub in DESTRUCTIVE_SUBCOMMANDS:
        return "destructive"
    if sub == "auth":
        return "safe" if "can-i" in argv else "mutating"
    if sub == "config":
        return "safe" if "view" in argv else "mutating"
    if sub in MUTATING_SUBCOMMANDS:
        return "mutating"
    if sub in SAFE_SUBCOMMANDS:
        return "safe"
    return "mutating"  # unknown subcommand: never assume read-only


def _analyze_one(argv: list) -> KubeCmd | None:
    head = next((t for t in argv if "=" not in t or not t.split("=", 1)[0].isupper()), None)
    if head is None:
        return None
    base = head.rsplit("/", 1)[-1]
    if base not in KUBE_BINARIES:
        return None
    denied, namespaces, all_ns = [], [], False
    sub, resource = None, None
    i = argv.index(head) + 1
    while i < len(argv):
        tok = argv[i]
        flag = tok.split("=", 1)[0]
        if flag in DENIED_FLAGS:
            denied.append(flag)
            i += 1 if "=" in tok else 2
            continue
        if flag in ("-A", "--all-namespaces"):
            all_ns = True
            i += 1
            continue
        if flag in ("-n", "--namespace"):
            if "=" in tok:
                namespaces.append(tok.split("=", 1)[1])
                i += 1
            elif i + 1 < len(argv):
                namespaces.append(argv[i + 1])
                i += 2
            else:
                i += 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        if sub is None:
            sub = tok
        elif resource is None and sub not in ("exec", "rsh", "debug", "logs", "cp", "attach"):
            # first positional after the subcommand: kind[,kind][/name]
            resource = tok.split("/", 1)[0].split(",", 1)[0].lower()
        i += 1
    return KubeCmd(
        subcommand=sub,
        namespaces=tuple(namespaces),
        all_namespaces=all_ns,
        resource=resource,
        denied_flags=tuple(dict.fromkeys(denied)),
        classification=_classify_subcommand(sub, argv),
    )


def analyze(cmd) -> list:
    """All kube commands found in a command string / argv / pipeline.

    Returns a list of KubeCmd (empty when nothing kube-shaped). String
    input is shlex-split; `|` starts a new segment; unparseable text
    yields a sentinel destructive KubeCmd so callers fail closed.
    """
    if isinstance(cmd, str):
        try:
            lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            tokens = list(lex)
        except ValueError:
            return [KubeCmd(subcommand="<unparseable>", classification="destructive")]
    else:
        tokens = [str(t) for t in (cmd or [])]
    segments, _cur = [[]], []
    for t in tokens:
        if t == "|":
            segments.append([])
        else:
            segments[-1].append(t)
    out = []
    for seg in segments:
        k = _analyze_one(seg)
        if k is not None:
            out.append(k)
    return out


def classify_worst(cmd) -> str | None:
    """Worst-case classification across every kube command in `cmd`,
    or None when the text contains no kube command."""
    ks = analyze(cmd)
    if not ks:
        return None
    return max((k.classification for k in ks), key=lambda c: _SEVERITY[c])
