# TLS Curve/Group Pinning That Excludes ML-KEM

## Status
actionable

## When to apply
- Finding shows explicit TLS group/curve list containing only classical ECDH (X25519, P-256, P-384, P-521)
- `tls.Config.CurvePreferences`, OpenSSL `Groups`, Node.js `ecdhCurve`, Rust `kx_groups` set to classical-only
- TLS 1.3 handshake negotiates classical group despite peer supporting ML-KEM

## Anti-patterns (BEFORE — what to detect and remove)

### Go — explicit classical-only CurvePreferences

```go
cfg := &tls.Config{
    CurvePreferences: []tls.CurveID{
        tls.X25519,
        tls.CurveP256,
        tls.CurveP384,
    },
}
```

**Why it blocks PQC:** From Go 1.24, `CurvePreferences` acts as an allowlist. ML-KEM hybrids are dropped because they are not listed.

### OpenSSL — explicit classical group list

```c
SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
```

### Node.js — classical ecdhCurve

```javascript
const server = tls.createServer({
    ecdhCurve: 'X25519:P-256:P-384',
});
```

### Rust rustls — custom kx_groups

```rust
provider.kx_groups = vec![
    &aws_lc_rs::kx_group::X25519,
    &aws_lc_rs::kx_group::SECP256R1,
];
```

## Fix patterns (AFTER — the remediation)

### Go — delete CurvePreferences (preferred)

```go
cfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
    // CurvePreferences intentionally unset — defaults include ML-KEM
}
```

### Go — explicit list including PQ (when curation required)

```go
cfg.CurvePreferences = []tls.CurveID{
    tls.X25519MLKEM768,
    tls.X25519,
    tls.CurveP256,
    tls.CurveP384,
}
```

### OpenSSL — use defaults or include PQ

```c
// Omit SSL_CTX_set1_groups_list entirely (OpenSSL 3.5+ defaults include ML-KEM)
// Or explicitly:
SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256");
```

### Node.js — remove ecdhCurve

```javascript
const server = tls.createServer({ /* no ecdhCurve — use defaults */ });
```

### Rust — use default provider

```rust
let config = rustls::ClientConfig::builder_with_provider(
    aws_lc_rs::default_provider().into(),
)...;
```

## Detection

```bash
rg -n 'CurvePreferences\s*:' '**/*.go'
rg -n 'set1_groups(_list)?\s*\(' '**/*.{c,cc,cpp,h}'
rg -n 'ecdhCurve\s*:' '**/*.{js,ts}'
rg -n 'kx_groups\s*:' '**/*.rs'
rg -n 'set_ecdh_curve|set_groups' '**/*.py'
rg -n 'ssl_ecdh_curve|SSLOpenSSLConfCmd\s+Groups' '**/*'
```

## Key constraints
- Go `CurvePreferences` is an **allowlist**, not a preference order (Go 1.24+)
- ML-KEM hybrids are TLS 1.3 only — `MinVersion` must allow TLS 1.3
- Do not conflate with cipher-suite pinning — `CipherSuites` does not control key-exchange groups in TLS 1.3
- Client effect: no PQ key share in ClientHello
- Server effect: prevents PQ even if client supports it

## Runtime defaults (what emerges when you remove the pin)

| Runtime | Default PQ KX | Hybrid group names |
|---|---|---|
| Go 1.24+ | `X25519MLKEM768` | CurveID 4588 |
| OpenSSL 3.5+ | ML-KEM in DEFAULT | `X25519MLKEM768`, `P256-MLKEM768` |
| Node.js 22+ | PQ in default (OpenSSL 3.5) | same as OpenSSL |
| rustls (aws-lc-rs) | `X25519MLKEM768` first | `X25519MLKEM768` |

## FIPS interaction
- Prefer `SecP256r1MLKEM768` / `SecP384r1MLKEM1024` in explicit FIPS allowlists — NIST-curve hybrids align with FIPS
- `X25519MLKEM768` in FIPS: OpenSSL FIPS provider excludes it; only NIST-curve hybrids work
- Classical-only `CurvePreferences` still blocks PQ under FIPS — same fix applies

## Evidence
- [crypto/tls Config.CurvePreferences](https://pkg.go.dev/crypto/tls#Config.CurvePreferences) — allowlist semantics
- [Go 1.24 Release Notes](https://go.dev/doc/go1.24) — order ignored
- [OpenSSL SSL_CTX_set1_groups_list](https://docs.openssl.org/3.6/man3/SSL_CTX_set1_groups_list/) — PQ group names
- [rustls defaults](https://docs.rs/rustls/latest/rustls/manual/_05_defaults/index.html) — X25519MLKEM768 priority
- [IANA TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8) — code points 4587-4589
