"""Playwright browser adapter for web security validation."""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import ClassVar

try:
    from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


SAFE_VERBS = frozenset(
    {
        "navigate",
        "screenshot",
        "har-capture",
        "inspect-cookies",
        "check-headers",
        "check-csp",
        "dom-query",
    }
)
MUTATING_VERBS = frozenset(
    {
        "authenticate",
        "csrf-replay",
        "form-submit",
        "xhr-probe",
        "xss-inject",
        "clickjack-probe",
        "redirect-probe",
        "session-fixation",
        "websocket-probe",
    }
)


@dataclass
class StepResult:
    step_id: str
    verb: str
    target: dict
    classification: str
    verdict: str
    expected: str = ""
    observed: str = ""
    evidence: list[dict] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    finding_ref: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", 0, [])}


def classify(verb: str) -> str:
    if verb in SAFE_VERBS:
        return "safe"
    return "mutating" if verb in MUTATING_VERBS else "unknown"


class BrowserAdapter:
    """Manages Playwright lifecycle and dispatches verb handlers."""

    def __init__(self):
        self._pw = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._ws = os.environ.get("PLAYWRIGHT_WS_ENDPOINT", "ws://localhost:3000/")

    def __enter__(self) -> BrowserAdapter:
        self._connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def current_url(self) -> str:
        """URL of the active page, or empty if not connected."""
        if self._page is None:
            return ""
        try:
            return self._page.url or ""
        except Exception:
            return ""

    def _connect(self) -> None:
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("playwright not installed: pip install playwright")
        if self._page:
            return

        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.connect(self._ws)
        except Exception:
            self._browser = self._pw.chromium.launch(headless=True)

        self._context = self._browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        self._page = self._context.new_page()

    def close(self) -> None:
        for resource in (self._context, self._browser):
            if resource:
                resource.close()
        if self._pw:
            self._pw.stop()
        self._page = self._context = self._browser = self._pw = None

    def execute(self, step: dict, artifacts_dir: Path) -> StepResult:
        t0 = time.monotonic()
        verb = step.get("verb", "")
        sid = step.get("id", "unknown")
        cls_tag = step.get("classification", classify(verb))
        target = step.get("target", {}) or {}
        payload = step.get("payload", {}) or {}
        expected = step.get("expected", "")

        self._connect()

        handler = self._dispatch.get(verb)
        if not handler:
            return self._result(
                sid,
                verb,
                target,
                cls_tag,
                "not_attempted",
                observed=f"unsupported verb: {verb}",
                duration_ms=self._elapsed(t0),
            )

        try:
            result = handler(self, sid, target, payload, expected, artifacts_dir)
        except Exception as e:
            result = self._result(
                sid,
                verb,
                target,
                cls_tag,
                "inconclusive",
                observed=f"{type(e).__name__}: {e}",
                duration_ms=self._elapsed(t0),
            )

        result.duration_ms = self._elapsed(t0)
        result.finding_ref = step.get("finding_ref")
        return result

    # --- Verb handlers ---

    def _navigate(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", "")
        resp = self._page.goto(url, wait_until="networkidle", timeout=30000)
        status = resp.status if resp else 0
        verdict = "confirmed" if 200 <= status < 400 else "inconclusive"
        return self._result(
            sid,
            "navigate",
            target,
            "safe",
            verdict,
            expected=expected,
            observed=f"status={status} url={self._page.url}",
        )

    def _screenshot(self, sid, target, payload, expected, arts) -> StepResult:
        path = arts / f"{sid}.png"
        self._page.screenshot(path=str(path), full_page=True)
        return self._result(
            sid,
            "screenshot",
            target,
            "safe",
            "confirmed",
            expected=expected,
            observed=f"saved {path.name}",
            evidence=[{"type": "screenshot", "path": str(path)}],
        )

    def _har_capture(self, sid, target, payload, expected, arts) -> StepResult:
        har_path = arts / f"{sid}.har"
        url = target.get("url", self._page.url)
        ctx = self._browser.new_context(record_har_path=str(har_path), ignore_https_errors=True)
        page = ctx.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)
        ctx.close()
        return self._result(
            sid,
            "har-capture",
            target,
            "safe",
            "confirmed",
            expected=expected,
            observed=f"HAR: {har_path.name}",
            evidence=[{"type": "har", "path": str(har_path)}],
        )

    def _inspect_cookies(self, sid, target, payload, expected, arts) -> StepResult:
        cookies = self._context.cookies()
        out = arts / f"{sid}.cookies.json"
        out.write_text(json.dumps(cookies, indent=2), encoding="utf-8")
        summary = (
            "; ".join(
                f"{c['name']}(SameSite={c.get('sameSite', 'unset')}, "
                f"Secure={c.get('secure', False)}, HttpOnly={c.get('httpOnly', False)})"
                for c in cookies
            )
            or "no cookies"
        )
        return self._result(
            sid,
            "inspect-cookies",
            target,
            "safe",
            "confirmed",
            expected=expected,
            observed=summary,
            evidence=[{"type": "cookies", "path": str(out)}],
        )

    def _check_headers(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", self._page.url)
        resp = self._page.goto(url, wait_until="commit", timeout=15000)
        headers = dict(resp.headers) if resp else {}
        out = arts / f"{sid}.headers.json"
        out.write_text(json.dumps(headers, indent=2), encoding="utf-8")

        _SECURITY = {
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        }
        sec = {k: v for k, v in headers.items() if k.lower() in _SECURITY}
        observed = json.dumps(sec) if sec else "no security headers"
        return self._result(
            sid,
            "check-headers",
            target,
            "safe",
            "confirmed",
            expected=expected,
            observed=observed,
            evidence=[{"type": "headers", "path": str(out)}],
        )

    def _check_csp(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", self._page.url)
        resp = self._page.goto(url, wait_until="commit", timeout=15000)
        csp = resp.headers.get("content-security-policy", "") if resp else ""
        return self._result(
            sid,
            "check-csp",
            target,
            "safe",
            "confirmed" if csp else "refuted",
            expected=expected,
            observed=csp or "no CSP header",
        )

    def _dom_query(self, sid, target, payload, expected, arts) -> StepResult:
        selector = payload.get("selector", target.get("selector", "body"))
        elements = self._page.query_selector_all(selector)
        texts = [el.inner_text()[:200] for el in elements[:10]]
        return self._result(
            sid,
            "dom-query",
            target,
            "safe",
            "confirmed" if elements else "refuted",
            expected=expected,
            observed=f"{len(elements)} matches: {texts[:3]}",
        )

    def _authenticate(self, sid, target, payload, expected, arts) -> StepResult:
        creds = payload or target.get("credentials", {})
        login_url = creds.get("login_url") or target.get("url", "")
        user_sel = creds.get("username_selector", 'input[name="username"], input[type="text"]')
        pass_sel = creds.get("password_selector", 'input[name="password"], input[type="password"]')
        submit_sel = creds.get("submit_selector", 'button[type="submit"]')

        self._page.goto(login_url, wait_until="networkidle", timeout=30000)
        self._page.wait_for_selector(user_sel, timeout=10000).fill(creds.get("username", ""))
        self._page.wait_for_selector(pass_sel, timeout=5000).fill(creds.get("password", ""))

        with self._page.expect_navigation(wait_until="networkidle", timeout=15000):
            self._page.click(submit_sel)

        session = [
            c
            for c in self._context.cookies()
            if c.get("httpOnly") or "session" in c["name"].lower()
        ]

        if session:
            return self._result(
                sid,
                "authenticate",
                target,
                "mutating",
                "confirmed",
                expected=expected,
                observed=f"authenticated; {len(session)} session cookie(s)",
            )
        return self._result(
            sid,
            "authenticate",
            target,
            "mutating",
            "inconclusive",
            expected=expected,
            observed="login submitted but no session cookies",
        )

    def _csrf_replay(self, sid, target, payload, expected, arts) -> StepResult:
        attack_url = target.get("url", "")
        victim_origin = payload.get("victim_origin", "")

        # Fresh page so form auto-submit doesn't corrupt session page
        attack_page = self._context.new_page()
        captured: list[dict] = []

        def intercept(req):
            if victim_origin and req.url.startswith(victim_origin):
                captured.append(
                    {"url": req.url, "method": req.method, "headers": dict(req.headers)}
                )

        attack_page.on("request", intercept)
        with contextlib.suppress(Exception):  # form auto-submit interrupts navigation — expected
            attack_page.goto(attack_url, wait_until="networkidle", timeout=30000)
        attack_page.wait_for_timeout(3000)
        attack_page.remove_listener("request", intercept)

        out = arts / f"{sid}.csrf-requests.json"
        out.write_text(json.dumps(captured, indent=2), encoding="utf-8")

        ss = arts / f"{sid}.post-csrf.png"
        attack_page.screenshot(path=str(ss))
        attack_page.close()

        evidence = [
            {"type": "requests", "path": str(out)},
            {"type": "screenshot", "path": str(ss)},
        ]

        if not captured:
            return self._result(
                sid,
                "csrf-replay",
                target,
                "mutating",
                "refuted",
                expected=expected,
                observed="no cross-origin requests to victim",
                evidence=evidence,
            )

        req = captured[0]
        has_cookie = "cookie" in req["headers"]
        sfs = req["headers"].get("sec-fetch-site", "n/a")

        if has_cookie:
            return self._result(
                sid,
                "csrf-replay",
                target,
                "mutating",
                "confirmed",
                expected=expected,
                observed=(
                    f"CSRF confirmed: {req['method']} {req['url']}"
                    f" cookies sent (sec-fetch-site={sfs})"
                ),
                evidence=evidence,
            )
        return self._result(
            sid,
            "csrf-replay",
            target,
            "mutating",
            "refuted",
            expected=expected,
            observed=f"no cookies attached: {req['method']} {req['url']} (sec-fetch-site={sfs})",
            evidence=evidence,
        )

    def _form_submit(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", self._page.url)
        if url != self._page.url:
            self._page.goto(url, wait_until="networkidle", timeout=15000)

        for sel, val in payload.get("fields", {}).items():
            self._page.fill(sel, val)

        form_sel = payload.get("form_selector", "form")
        with self._page.expect_navigation(wait_until="networkidle", timeout=15000):
            self._page.eval_on_selector(form_sel, "el => el.submit()")

        return self._result(
            sid,
            "form-submit",
            target,
            "mutating",
            "confirmed",
            expected=expected,
            observed=f"submitted, landed on {self._page.url}",
        )

    def _xhr_probe(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", "")
        method = payload.get("method", "GET")

        result = self._page.evaluate(f"""async () => {{
            try {{
                const r = await fetch("{url}",
                    {{method:"{method}", credentials:"include", mode:"cors"}});
                return {{status: r.status, ok: r.ok, type: r.type}};
            }} catch(e) {{ return {{error: e.message}}; }}
        }}""")

        out = arts / f"{sid}.xhr.json"
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")

        if "error" in result:
            verdict, observed = "refuted", f"XHR blocked: {result['error']}"
        elif result.get("ok"):
            verdict, observed = (
                "confirmed",
                f"XHR succeeded: status={result['status']} type={result.get('type')}",
            )
        else:
            verdict, observed = (
                "inconclusive",
                f"XHR status={result.get('status')} type={result.get('type')}",
            )

        return self._result(
            sid,
            "xhr-probe",
            target,
            "mutating",
            verdict,
            expected=expected,
            observed=observed,
            evidence=[{"type": "xhr", "path": str(out)}],
        )

    def _xss_inject(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", "")
        xss = payload.get("payload", "<img src=x onerror=alert(1)>")
        param = payload.get("param", "q")

        sep = "&" if "?" in url else "?"
        self._page.goto(f"{url}{sep}{param}={xss}", wait_until="networkidle", timeout=15000)
        reflected = xss in self._page.content()

        ss = arts / f"{sid}.xss.png"
        self._page.screenshot(path=str(ss))

        verdict = "confirmed" if reflected else "refuted"
        observed = "XSS reflected unescaped" if reflected else "XSS sanitized/not reflected"
        return self._result(
            sid,
            "xss-inject",
            target,
            "mutating",
            verdict,
            expected=expected,
            observed=observed,
            evidence=[{"type": "screenshot", "path": str(ss)}],
        )

    def _clickjack_probe(self, sid, target, payload, expected, arts) -> StepResult:
        victim_url = target.get("url", "")
        self._page.set_content(
            f'<html><body><iframe id="t" src="{victim_url}" '
            f'style="width:100%;height:600px;opacity:0.5"></iframe></body></html>'
        )
        self._page.wait_for_timeout(3000)

        try:
            self._page.frame_locator("#t").locator("body").wait_for(timeout=5000)
            framed = True
        except Exception:
            framed = False

        ss = arts / f"{sid}.clickjack.png"
        self._page.screenshot(path=str(ss))

        verdict = "confirmed" if framed else "refuted"
        observed = "loaded in iframe" if framed else "refused to frame (X-Frame-Options/CSP)"
        return self._result(
            sid,
            "clickjack-probe",
            target,
            "mutating",
            verdict,
            expected=expected,
            observed=observed,
            evidence=[{"type": "screenshot", "path": str(ss)}],
        )

    def _redirect_probe(self, sid, target, payload, expected, arts) -> StepResult:
        url = target.get("url", "")
        evil = payload.get("redirect_to", "https://evil.example.com")

        test_url = url.replace("REDIRECT_TARGET", evil)
        if test_url == url:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}redirect_uri={evil}"

        resp = self._page.goto(test_url, wait_until="networkidle", timeout=15000)
        final = self._page.url

        if evil in final:
            verdict, observed = "confirmed", f"open redirect to {final}"
        elif resp and resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location", "")
            if evil in loc:
                verdict, observed = "confirmed", f"redirect header → {loc}"
            else:
                verdict, observed = "refuted", f"redirected elsewhere: {final}"
        else:
            verdict, observed = "refuted", f"no redirect, stayed on {final}"

        return self._result(
            sid,
            "redirect-probe",
            target,
            "mutating",
            verdict,
            expected=expected,
            observed=observed,
        )

    # --- Helpers ---

    _dispatch: ClassVar[dict[str, Callable]] = {}

    @staticmethod
    def _result(sid: str, verb: str, target: dict, cls: str, verdict: str, **kw) -> StepResult:
        return StepResult(
            step_id=sid,
            verb=verb,
            target=target,
            classification=cls,
            verdict=verdict,
            **kw,
        )

    @staticmethod
    def _elapsed(t0: float) -> int:
        return int((time.monotonic() - t0) * 1000)


# Register dispatch table (avoids repeating method names)
BrowserAdapter._dispatch = {
    "navigate": BrowserAdapter._navigate,
    "screenshot": BrowserAdapter._screenshot,
    "har-capture": BrowserAdapter._har_capture,
    "inspect-cookies": BrowserAdapter._inspect_cookies,
    "check-headers": BrowserAdapter._check_headers,
    "check-csp": BrowserAdapter._check_csp,
    "dom-query": BrowserAdapter._dom_query,
    "authenticate": BrowserAdapter._authenticate,
    "csrf-replay": BrowserAdapter._csrf_replay,
    "form-submit": BrowserAdapter._form_submit,
    "xhr-probe": BrowserAdapter._xhr_probe,
    "xss-inject": BrowserAdapter._xss_inject,
    "clickjack-probe": BrowserAdapter._clickjack_probe,
    "redirect-probe": BrowserAdapter._redirect_probe,
}
