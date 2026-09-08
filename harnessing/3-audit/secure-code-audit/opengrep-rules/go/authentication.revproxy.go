package rules

// Fixture for the reverse-proxy-without-strip branch (file-level
// co-occurrence): this file mentions identity headers and constructs a
// reverse proxy but never strips/deletes any of them — the oauth-proxy
// FIND-003 shape, where the vulnerability is the ABSENCE of a strip.
// (The file-level scan covers comments too, so this comment must not
// spell the deletion call's name.)

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

var passHeaders = []string{
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Access-Token",
}

func newUpstreamProxy(target *url.URL) http.Handler {
	// ruleid: traust-go-authentication-forwarded-identity-passthrough
	proxy := httputil.NewSingleHostReverseProxy(target)
	return proxy
}
