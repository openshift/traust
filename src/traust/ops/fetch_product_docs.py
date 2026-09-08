#!/usr/bin/env python3
"""Official-docs fetcher (doc-variance lane P1 — the deterministic leg).

Fetches docs.redhat.com product documentation for one (product,
version): enumerates the guides on the landing page, downloads each
guide's single-page HTML, strips it to plain text with section anchors
preserved, and writes a manifest — the input the claims-extraction
stage reads. Deterministic and cached: re-runs skip already-fetched
guides unless --refresh; every artifact records its canonical URL and
fetch time (provenance for the ≤600-char quote + URL attribution rule,
CC-BY-SA).

This script fetches and structures; it never extracts claims or judges
anything (docs/deterministic-inferential-mix.md discipline). Output
is a WORK directory (default: per-user ~/.cache), not a campaign artifact —
variance records, not doc mirrors, are what persists (plan §4: no doc
mirroring; share-alike + audit noise).

Usage:
    python3 fetch_product_docs.py --product <slug> --version <v>
        [--guides g1,g2 | --all-guides] [--work-dir DIR] [--refresh]
Exit 0 with a manifest; 1 on fetch failure (loud, never partial-silent).
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import re
import subprocess
import sys
from pathlib import Path

BASE = "https://docs.redhat.com"


def _get(url: str) -> str:
    # curl with its DEFAULT client shape: the docs CDN 403s both
    # python-urllib and custom UA strings; stock curl passes. Public
    # site, no credentials — argv is clean (S5 concerns none).
    proc = subprocess.run(
        ["curl", "-sSL", "--fail", "--max-time", "60", url], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"curl failed for {url}: {proc.stderr.strip()[:200]}")
    return proc.stdout


def list_guides(product: str, version: str) -> list[str]:
    landing = f"{BASE}/en/documentation/{product}/{version}"
    page = _get(landing)
    pat = rf'href="(/en/documentation/{re.escape(product)}/'
    pat += rf'{re.escape(version)}/html/([^"/]+))"'
    guides = sorted({m.group(2) for m in re.finditer(pat, page)})
    if not guides:
        raise SystemExit(
            f"no guides found at {landing} — wrong slug/version, or the page layout changed"
        )
    return guides


_TAG_RX = re.compile(r"<[^>]+>")
_HEAD_RX = re.compile(r"<h([1-4])([^>]*)>(.*?)</h\1>", re.S)
_ID_RX = re.compile(r'id="([^"]*)"')
_HREF_RX = re.compile(r'href="#([^"]+)"')
_COPYLINK_RX = re.compile(r"Copy link(Link copied to clipboard!?)?\s*$")
_DROP_RX = re.compile(r"<(script|style|nav|header|footer)\b.*?</\1>", re.S | re.I)


def strip_to_text(html_src: str, base_url: str) -> str:
    """Plain text with section anchors as '## <title> [<url>#<id>]'
    markers, so extracted claims can cite canonical section URLs."""
    src = _DROP_RX.sub("", html_src)
    out, pos = [], 0
    for m in _HEAD_RX.finditer(src):
        chunk = src[pos : m.start()]
        out.append(html.unescape(_TAG_RX.sub(" ", chunk)))
        title = _COPYLINK_RX.sub("", html.unescape(_TAG_RX.sub("", m.group(3))).strip()).strip()
        # anchor: heading-tag id, else the copy-link widget's href="#..."
        # INSIDE the heading (docs.redhat.com puts ids on wrappers, but
        # every heading embeds its own copy-link anchor)
        idm = _ID_RX.search(m.group(2)) or _HREF_RX.search(m.group(3))
        anchor = f"{base_url}#{idm.group(1)}" if idm else base_url
        out.append(f"\n\n## {title} [{anchor}]\n")
        pos = m.end()
    out.append(html.unescape(_TAG_RX.sub(" ", src[pos:])))
    text = "\n".join(re.sub(r"[ \t]+", " ", ln).strip() for ln in "".join(out).splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def fetch(product: str, version: str, guides: list[str], work: Path, refresh: bool) -> dict:
    """Fetches product manifest data"""
    work.mkdir(parents=True, exist_ok=True)
    manifest = {
        "artifact": "product-docs-fetch",
        "product": product,
        "version": version,
        "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "license_note": (
            "CC-BY-SA content — structured for claim "
            "extraction only; quotes in variance records "
            "stay <=600 chars with the canonical URL as "
            "attribution; this work dir is scratch, never "
            "a committed mirror"
        ),
        "guides": [],
    }
    for g in guides:
        url = f"{BASE}/en/documentation/{product}/{version}/html-single/{g}/index"
        txt_path = work / f"{g}.txt"
        if txt_path.is_file() and not refresh:
            state = "cached"
        else:
            try:
                page = _get(url)
            except Exception as e:
                raise SystemExit(
                    f"fetch FAILED for {url}: {e} — refusing a partial-silent manifest"
                ) from None
            txt_path.write_text(strip_to_text(page, url), encoding="utf-8")
            state = "fetched"
        manifest["guides"].append(
            {
                "guide": g,
                "url": url,
                "text": txt_path.name,
                "bytes": txt_path.stat().st_size,
                "state": state,
            }
        )
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--guides", help="comma-separated guide slugs")
    g.add_argument("--all-guides", action="store_true")
    ap.add_argument("--work-dir", type=Path, default=None)
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args(argv)

    guides = (
        [s.strip() for s in args.guides.split(",")]
        if args.guides
        else list_guides(args.product, args.version)
    )
    # per-user cache, never a fixed /tmp path (S6)
    work = args.work_dir or (
        Path.home() / ".cache" / "traust" / "doc-variance" / args.product / args.version
    )
    m = fetch(args.product, args.version, guides, work, args.refresh)
    total = sum(g["bytes"] for g in m["guides"])
    print(
        f"{args.product}@{args.version}: {len(m['guides'])} guide(s), "
        f"{total:,} bytes text -> {work}/manifest.json"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
