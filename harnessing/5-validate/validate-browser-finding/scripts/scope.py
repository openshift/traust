"""Browser validation scope — origin allowlists, verb restrictions, engagement expiry."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None


def _origin(url: str) -> str | None:
    """Return scheme://host[:port] for a URL, or None if unparseable."""
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".lower()


@dataclass
class BrowserTarget:
    victim_origin: str
    attacker_origins: list[str] = field(default_factory=list)
    credentials: dict = field(default_factory=dict)
    allowed_verbs: list[str] = field(default_factory=list)

    def matches_url(self, url: str) -> bool:
        origin = _origin(url)
        if not origin:
            return False
        allowed = [_origin(self.victim_origin), *(_origin(ao) for ao in self.attacker_origins)]
        return origin in {a for a in allowed if a}

    def allows_verb(self, verb: str) -> bool:
        # Fail closed: missing/empty allowed_verbs denies everything.
        return bool(self.allowed_verbs) and verb in self.allowed_verbs


@dataclass
class Scope:
    engagement: str | None = None
    authorized_by: str | None = None
    expires: _dt.date | None = None
    environment: str = "lab"
    targets: list[BrowserTarget] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"targets.yaml not found: {p}")

        data = _parse(p)
        meta = data.get("metadata", data.get("meta", {}))

        scope = cls(
            engagement=meta.get("engagement") or data.get("engagement"),
            authorized_by=meta.get("authorized_by") or data.get("authorized_by"),
            environment=meta.get("environment") or data.get("environment", "lab"),
        )

        if exp := (meta.get("expires") or data.get("expires")):
            scope.expires = _dt.date.fromisoformat(exp) if isinstance(exp, str) else exp

        scope.targets = [
            BrowserTarget(
                victim_origin=b["victim_origin"],
                attacker_origins=b.get("attacker_origins", []),
                credentials=b.get("credentials", {}),
                allowed_verbs=b.get("allowed_verbs", []),
            )
            for b in data.get("browser", [])
        ]
        return scope

    @property
    def is_expired(self) -> bool:
        return bool(self.expires and _dt.date.today() > self.expires)

    def check(self, verb: str, url: str) -> tuple[bool, str]:
        if self.is_expired:
            return False, "engagement expired"
        if not self.targets:
            return False, "no browser targets defined"

        # Fail closed: every scoped action needs a concrete URL so we can
        # bind the verb to the origin actually being acted on.
        if not url:
            return False, "url required for scope check"

        target = self._match_target(url)
        if not target:
            return False, f"url '{url}' not in any target origin"

        if verb and not target.allows_verb(verb):
            return False, f"verb '{verb}' not in allowed_verbs"

        return True, "ok"

    def credentials_for(self, url: str) -> dict:
        if target := self._match_target(url):
            return target.credentials
        return {}

    def _match_target(self, url: str) -> BrowserTarget | None:
        return next((t for t in self.targets if t.matches_url(url)), None)


def _parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    import json

    return json.loads(text)
