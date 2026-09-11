---
description: "Review pending finding dispositions and record identity-verified human decisions in the ledger."
---

Review and sign off pending disposition-ledger decisions using the countersign skill. Load the skill at .claude/skills/countersign/SKILL.md and follow its full procedure — build the decision-card inbox with python3 -m traust.cli tools countersign queue over $ARGUMENTS (a findings root or `<product>/<repo>`; default: the analysis-results/findings sibling), present ONE self-contained card per question (claim + machine refutation + lint-verified evidence as the option preview) with Confirm-false-positive / Keep-open / Defer choices, then record every decision in one `countersign.py apply` call — the signer is verified from their OIDC token — and show the receipt. Countersigned findings stay in the refuted register and remain overridable by execution evidence; keep-open requires the reviewer's own rationale; recording is refused if OIDC token verification fails.
