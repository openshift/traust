# TLS Server Key Exchange — Go

## Status
actionable

## When to apply
- Finding cites missing or hardcoded TLS config in a Go service
- TLS version pinned below platform profile (e.g. hardcoded `tls.VersionTLS12`)
- No mechanism to honor a platform-wide TLS security profile
- `CurvePreferences` set to classical-only groups (blocks ML-KEM negotiation)

## Approach selection

| Scenario | Approach |
|---|---|
| Service consuming a platform TLS profile (e.g. OCP, cloud LB policy) | Read profile from platform API, build `tls.Config`; **watch** for changes |
| Standalone Go service (no platform governance) | Let Go 1.24+ defaults handle ML-KEM; remove classical group pins |
| Downstream operator for upstream operand | Watch platform TLS profile; on change, **reload/restart operands** so they pick up the new config |

### Platform-specific integration (OpenShift example)

For OCP operators, use [controller-runtime-common/pkg/tls](https://github.com/openshift/controller-runtime-common/tree/main/pkg/tls)
which provides `SecurityProfileWatcher`, `FetchAPIServerTLSProfile`, and `NewTLSConfigFromProfile`.

For library-go operators, use `apiserver.ObserveTLSSecurityProfile` from `library-go/pkg/operator/configobserver/apiserver`.

For direct Go apps on OCP, fetch the APIServer CR (`apiservers.config.openshift.io/cluster`) and build `tls.Config` from the profile spec.

A one-shot read at startup is not enough. Customers can change the cluster TLS security profile at any time; the operator (or app) must keep a watch so new servers and existing operands adopt the updated config.

## Canonical fix patterns

### Standalone service — let Go defaults handle ML-KEM

Go 1.24+ negotiates `X25519MLKEM768` by default when `CurvePreferences` is nil.

```go
// BEFORE — blocks ML-KEM
srv := &http.Server{
    TLSConfig: &tls.Config{
        CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
        MinVersion:       tls.VersionTLS12,
    },
}

// AFTER — Go 1.24+ includes ML-KEM in defaults
srv := &http.Server{
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```

### Platform-governed service — read TLS config from platform

```go
func buildTLSConfigFromPlatform(profile PlatformTLSProfile) *tls.Config {
    cfg := &tls.Config{
        MinVersion: profile.MinTLSVersion(),
    }
    if profile.MinTLSVersion() < tls.VersionTLS13 {
        cfg.CipherSuites = profile.CipherSuites()
    }
    return cfg
}
```

The platform profile source depends on your environment:
- **OCP**: APIServer CR via controller-runtime-common or library-go
- **Cloud LB**: Load balancer cipher policy via cloud SDK
- **Managed service**: Platform-specific config API

### Watch for profile changes

Platform-governed services must watch the TLS profile (e.g. APIServer CR) rather than reading once at startup. When the watch reports a change:

1. **In-process servers** — exit-on-change (process restarts with the new `tls.Config`), or hot-reload without a restart via `tls.Config.GetConfigForClient`: return the current profile-derived config from the callback and every new handshake picks it up — the listener never restarts. Prefer `GetConfigForClient` for servers that must not drop connections (metrics, webhooks).
2. **Operators managing operands** — reload or restart the operands when the profile changes. Watching only inside the operator is insufficient; operands that terminated TLS with the old profile will not pick up the customer's new config until they are rolled.

## Key constraints

- Do NOT set `CurvePreferences` to classical-only groups — this blocks ML-KEM (Go >= 1.24 offers X25519MLKEM768 by default)
- Never use `InsecureSkipVerify`
- Set `NextProtos` / ALPN yourself — platform profiles typically do not set it
- TLS 1.3 cipher suites are not configurable in Go — they are always enabled
- Watch the profile for changes; operators must also reload operands on change

## Version thresholds

| Version | Capability |
|---|---|
| Go 1.24+ | ML-KEM (X25519MLKEM768) offered by default in TLS 1.3 handshakes |
| Go 1.26+ | NIST-curve hybrids (SecP256r1MLKEM768, SecP384r1MLKEM1024) for FIPS |
| Go 1.23 | No ML-KEM support |
