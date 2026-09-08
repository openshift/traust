package rules

import (
	"context"
	"net/http"
	"net/url"
)

func ssrf(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-ssrf-request-taint
	http.Get("https://" + r.URL.Query().Get("host") + "/status")

	// ruleid: traust-go-ssrf-request-taint
	http.NewRequest("GET", r.FormValue("url"), nil)

	// ruleid: traust-go-ssrf-request-taint
	http.NewRequestWithContext(context.TODO(), "POST", r.PostFormValue("target"), nil)

	// ok: traust-go-ssrf-request-taint
	http.Get("https://api.openshift.com/healthz")
}

func parsedAndValidated(w http.ResponseWriter, r *http.Request) {
	// sanitizer: structured parse precedes host validation — the
	// parse-then-validate idiom is the judge's business, not a raw taint
	u, err := url.Parse(r.URL.Query().Get("endpoint"))
	if err != nil || u.Hostname() != "api.openshift.com" {
		return
	}
	// ok: traust-go-ssrf-request-taint
	http.Get(u.String())
}

// The oapi-codegen generated-client FP mass (44/62 campaign dismissals —
// url.URL receivers feeding operator-configured base URLs into
// http.NewRequest) is excluded by PATH (*.gen.go, *_gen.go, *generated*),
// not by pattern: the confirmed TPs fire through the same url.URL shape
// in hand-written code. No fixture file can prove the path exclusion —
// `opengrep test` ignores paths filters (verified 2026-07-29) — so the
// exclusion is exercised at scan level (run_opengrep.py path) instead.
