#!/usr/bin/env python3
"""Compliance scope-entry writer (Phase 7 intake).

The ONLY sanctioned write path from /compliance-check interview into the
scope registry — the interview never hand-edits YAML. Every write:
schema-validates the resulting document, dry-run-resolves the new/updated
boundary (fail-loud: an entry that cannot resolve is refused, not
recorded), verifies the declarant against LDAP when --verified is
claimed, and refuses silent overwrites (updating an existing boundary
requires --update).

Identity rail (rail 2): a boundary declaration is a claim an auditor
holds someone to. With --verify-identity the declarant must be the holder
of the ledger identity token (`ledger auth login` / `ledger auth local`),
verified by the SDK, and must pass the deployment's optional employee-
directory cross-check (LEDGER_DIRECTORY_COMMAND); verification failure
records the entry as draft:<id>, never as signed. Without
--verify-identity the entry is ALWAYS draft:<id> — signing requires the
verification path.

Attestation bundles (rail 1) are NOT written here — attestations are
evidence, not scope; see the interview section of the compliance-check
SKILL for the bundle contract (owner_attestation entries in the
assessment artifact, informing evidence_review controls only).

Usage:
    python3 compliance_scope_intake.py \
        --boundary <id> --frameworks fw1,fw2 \
        --resolves-via repo-graph --product <node-id> \
        [--include repo=REASON ...] [--exclude repo=REASON ...] \
        --declared-by <kerberos-id> [--verify-identity] [--update] \
        [--notes TEXT] [--scope <yaml>] [--graph <json>] [--dry-run]

Exit 0 on a recorded (or dry-run-validated) entry; 1 on any refusal.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from traust_contracts.paths import schema_path
from traust_engine.compliance.scope import ScopeError

from traust.context import add_config_home_arg, load_engine

SCHEMA = schema_path("compliance-scope")

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def _pairs(items: list[str], flag: str) -> list[dict]:
    out = []
    for it in items:
        repo, sep, reason = it.partition("=")
        if not sep or not reason.strip():
            raise SystemExit(
                f"{flag} {it!r}: expected repo=REASON — the "
                f"rationale is mandatory, that is the point"
            )
        out.append({"repo": repo.strip(), "reason": reason.strip()})
    return out


def verify_identity(uid: str) -> bool:
    """The declarant is the ledger identity token holder.

    Resolves and verifies the current token (traust-ledger SDK), applies the
    deployment's optional employee-directory cross-check, and requires the
    verified identity to be ``uid`` (full identity, subject, or the local
    part of an email). False on any failure — fail closed. Until 2026-09-08
    this ran an LDAP lookup of the *typed* uid, which proved a name existed,
    not that the declarant held it.
    """
    try:
        from traust_ledger.auth.directory import apply_directory, load_directory
        from traust_ledger.cli.identity.actor import require_verified_actor

        actor = require_verified_actor()
        if actor is None or actor.kind != "human":
            return False
        actor = apply_directory(actor, load_directory())
    except Exception:
        return False
    want = (uid or "").strip().lower()
    have = {
        (actor.identity or "").lower(),
        (actor.identity_subject or "").lower(),
        (actor.identity or "").lower().split("@")[0],
    }
    return bool(want) and want in have


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument("--boundary", required=True)
    ap.add_argument("--frameworks", required=True, help="comma-separated framework ids")
    ap.add_argument("--resolves-via", required=True, choices=("repo-graph", "explicit"))
    ap.add_argument("--product", default=None)
    ap.add_argument("--include", action="append", default=[], metavar="repo=REASON")
    ap.add_argument("--exclude", action="append", default=[], metavar="repo=REASON")
    ap.add_argument("--declared-by", required=True, help="kerberos id of the boundary owner")
    ap.add_argument(
        "--verify-identity",
        action="store_true",
        help="LDAP-verify the declarant; without this (or on "
        "verification failure) the entry records as "
        "draft:<id>",
    )
    ap.add_argument("--update", action="store_true", help="required to modify an existing boundary")
    ap.add_argument("--notes", default=None)
    ap.add_argument("--scope", type=Path, default=None)
    ap.add_argument("--graph", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if yaml is None:
        sys.exit("PyYAML required")

    engine = load_engine(args.config_home)
    scope_path = args.scope or engine.compliance.scope_registry()
    graph_path = args.graph

    doc = {"version": 1, "updated": datetime.date.today().isoformat(), "boundaries": {}}
    if scope_path.is_file():
        doc = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    boundaries = doc.setdefault("boundaries", {})
    if args.boundary in boundaries and not args.update:
        sys.exit(
            f"boundary {args.boundary!r} already declared — pass "
            f"--update to modify it (silent overwrite refused)"
        )

    declared_by = args.declared_by
    if args.verify_identity:
        if verify_identity(args.declared_by):
            print(f"identity verified: {args.declared_by} (ledger token holder)")
        else:
            declared_by = f"draft:{args.declared_by}"
            print(f"identity NOT verified — recording as {declared_by}", file=sys.stderr)
    else:
        declared_by = f"draft:{args.declared_by}"

    entry = {
        "frameworks": [f.strip() for f in args.frameworks.split(",")],
        "resolves_via": args.resolves_via,
        "include": _pairs(args.include, "--include"),
        "exclude": _pairs(args.exclude, "--exclude"),
        "declared_by": declared_by,
        "declared_at": datetime.date.today().isoformat(),
    }
    if args.product:
        entry["product"] = args.product
    if args.notes:
        entry["notes"] = args.notes
    boundaries[args.boundary] = entry
    doc["updated"] = datetime.date.today().isoformat()

    # gate 1: schema
    try:
        import jsonschema

        jsonschema.validate(doc, json.loads(SCHEMA.read_text(encoding="utf-8")))
    except ImportError:
        sys.exit(
            "jsonschema required (the intake path is the validated "
            "path — that is its reason to exist)"
        )
    except jsonschema.ValidationError as e:
        sys.exit(f"entry fails the scope schema: {e.message}")

    # gate 2: dry-run resolution — an unresolvable declaration is refused
    try:
        res = engine.compliance.resolve(doc, args.boundary, graph_path)
    except ScopeError as e:
        sys.exit(f"entry does not resolve — refused, not recorded: {e}")

    if args.dry_run:
        print(
            f"DRY RUN ok: {args.boundary} -> {len(res['repos'])} repos "
            f"({'DRAFT' if res['draft'] else 'signed'})"
        )
        return 0

    scope_path.parent.mkdir(parents=True, exist_ok=True)
    with scope_path.open("w", encoding="utf-8") as f:
        f.write(
            "# Compliance scope registry — declared boundaries, "
            "resolved membership.\n"
            "# Schema: traust-contracts/compliance-scope.schema.json\n"
            "# Written via compliance_scope_intake.py — the interview "
            "path never hand-edits this file.\n"
        )
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
    print(
        f"recorded {args.boundary}: {len(res['repos'])} repos, "
        f"{'DRAFT' if res['draft'] else 'signed'} by {declared_by} "
        f"-> {scope_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
