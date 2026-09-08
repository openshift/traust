# TLS Client Key Exchange — Go

## Status
actionable

## When to apply
- Outbound TLS client config pins classical-only key exchange groups (`CurvePreferences` without ML-KEM)
- Client `MaxVersion` capped at TLS 1.2 (blocks TLS 1.3 hybrid key exchange)
- `GODEBUG=tlsmlkem=0` or `GODEBUG=tlssecpmlkem=0` in Dockerfile, deployment manifest, or environment
- Copy-pasted "secure TLS" boilerplate applied to HTTP/gRPC/DB clients with unnecessary restrictions
- Finding cites `tls-client`, `http-client`, `grpc-client`, or `db-client` context

Unlike servers, clients do **not** need to read a platform TLS profile for PQC readiness. Go 1.24+ negotiates `X25519MLKEM768` by default when the client config does not restrict groups or TLS version. The fix is usually **removing** restrictions, not adding PQC code.

## Approach selection

| Scenario | Approach |
|---|---|
| `net/http` client with custom `Transport.TLSClientConfig` | Delete `CurvePreferences`, `MaxVersion`, and classical-only `CipherSuites` pins; keep `RootCAs`, `ServerName`, `Certificates` |
| gRPC client (`credentials.NewTLS`) | Pass minimal `tls.Config` (CA pool + optional client cert); no group/version caps |
| PostgreSQL (`pgx` / `pgconn`) | `Config.TLSConfig` — remove restrictions; fix `InsecureSkipVerify` |
| MySQL (`go-sql-driver/mysql`) | `RegisterTLSConfig` / `mysql.Config.TLS` — remove restrictions |
| Shared TLS helper used by outbound clients | Delete classical-only `CurvePreferences`; split server vs client builders if needed |
| `GODEBUG=tlsmlkem=0` in image/manifest | Remove the override; ensure `go` directive in `go.mod` is >= 1.24 |

## Canonical fix patterns

### HTTP client — remove classical group pin

```go
// BEFORE — blocks ML-KEM
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: rootPool,
            CurvePreferences: []tls.CurveID{
                tls.X25519, tls.CurveP256, tls.CurveP384,
            },
            MinVersion: tls.VersionTLS12,
        },
    },
}

// AFTER — Go 1.24+ includes ML-KEM in defaults
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs:    rootPool,
            ServerName: "api.example.com",
            MinVersion: tls.VersionTLS12,
        },
    },
}
```

### gRPC client

```go
// BEFORE
creds := credentials.NewTLS(&tls.Config{
    RootCAs:          rootPool,
    CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
})

// AFTER
creds := credentials.NewTLS(&tls.Config{
    RootCAs: rootPool,
})
```

### Database clients

```go
// PostgreSQL (pgx) — AFTER
config.ConnConfig.TLSConfig = &tls.Config{
    RootCAs:    rootPool,
    ServerName: "postgres.example.svc",
}

// MySQL (go-sql-driver) — AFTER
mysql.RegisterTLSConfig("custom", &tls.Config{
    RootCAs:    rootPool,
    ServerName: "mysql.example.svc",
})
```

### GODEBUG override

```dockerfile
# BEFORE — disables ML-KEM
ENV GODEBUG=tlsmlkem=0

# AFTER — remove; rely on Go 1.24+ defaults
```

### go.mod directive

An old `go` directive causes the toolchain to apply historical GODEBUG defaults.

```
// BEFORE
go 1.21

// AFTER
go 1.24
```

### Trust-only client builder (preferred pattern)

```go
func newOutboundTLSConfig(caPEM []byte, serverName string) (*tls.Config, error) {
    pool := x509.NewCertPool()
    if !pool.AppendCertsFromPEM(caPEM) {
        return nil, fmt.Errorf("failed to parse CA")
    }
    return &tls.Config{
        RootCAs:    pool,
        ServerName: serverName,
        MinVersion: tls.VersionTLS12,
    }, nil
}
```

## Key constraints

- **Clients must not restrict TLS negotiation** — must support TLS 1.3 and ML-KEM groups
- Do **not** set `CurvePreferences` to classical-only groups — this filters out ML-KEM
- Do **not** set `MaxVersion: tls.VersionTLS12` on clients — ML-KEM requires TLS 1.3
- Do **not** set `GODEBUG=tlsmlkem=0` — reverts to pre-PQC defaults
- `MinVersion: tls.VersionTLS12` is acceptable — it is a floor, not a ceiling
- `CipherSuites` affect TLS 1.2 only — Go ignores them for TLS 1.3
- Never use `InsecureSkipVerify: true`
- Do **not** apply server-side platform TLS profile restrictions to outbound clients
- Infrastructure-governed endpoints (DB, LDAP): fixing the client removes the blocker; end-to-end ML-KEM still requires a PQC-capable server peer

## Version thresholds

| Version | Capability |
|---|---|
| Go 1.24+ | `X25519MLKEM768` in default key exchange when `CurvePreferences` is nil |
| Go 1.23 | No ML-KEM support |
| `GODEBUG=tlsmlkem=0` | Disables `X25519MLKEM768` from defaults (Go 1.24+) |
| `go` directive < 1.24 in `go.mod` | May inherit pre-1.24 GODEBUG defaults even with newer toolchain |

## Evidence

- [golang/go#69985](https://github.com/golang/go/issues/69985) — X25519MLKEM768 enabled by default
- [Go GODEBUG docs](https://go.dev/doc/godebug) — `tlsmlkem` (Go 1.24)
- [crypto/tls Config.CurvePreferences](https://pkg.go.dev/crypto/tls#Config.CurvePreferences) — nil → defaults include ML-KEM
