# TLS Server Key Exchange — Rust

## Status
actionable

## When to apply
- Finding cites missing or hardcoded TLS config in a Rust service
- TLS version pinned below platform profile
- No mechanism to read or honor a platform-wide TLS security profile
- Using `danger_accept_invalid_certs(true)` (reqwest) or equivalent

## Approach selection

Backend preference: `openssl` crate (system OpenSSL) or `native-tls` first —
they ride the platform's FIPS-validated provider and inherit its PQC
timeline. `rustls` only where FIPS is out of scope. The observer pattern
below is identical across all three; only the acceptor type differs.

| Scenario | Approach |
|---|---|
| Rust service with `openssl` crate (FIPS compliance) | Read platform TLS config → build `SslContext` / `SslAcceptor` |
| Rust service with `native-tls` | Read platform TLS config → build `native_tls::TlsAcceptor` (delegates to system OpenSSL on Linux — same FIPS posture) |
| Rust service with `rustls` (non-FIPS) | Read platform TLS config → build `ServerConfig` |
| Standalone service (no platform governance) | Use rustls 0.23.27+ defaults for ML-KEM, or system OpenSSL >= 3.5 via the crates above |
| axum / hyper server | Same fetch, swap acceptor via `tokio::sync::watch` channel |

## Canonical fix patterns

### Standalone service — rustls defaults

rustls 0.23.27+ with `aws-lc-rs` backend negotiates ML-KEM by default.

```rust
use rustls::ServerConfig;
use std::sync::Arc;

let config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
let config = Arc::new(config);
```

### Platform-governed service — read TLS config

```rust
fn build_ssl_context(
    spec: &TLSProfileSpec,
    certfile: &str,
    keyfile: &str,
) -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(to_ssl_version(&spec.min_tls_version)))?;
    if !spec.ciphers.is_empty() {
        builder.set_cipher_list(&spec.ciphers.join(":"))?;
    }
    builder.set_certificate_chain_file(certfile)?;
    builder.set_private_key_file(keyfile, openssl::ssl::SslFiletype::PEM)?;
    Ok(builder.build().into_context())
}
```

The profile source depends on your platform:
- **OCP**: APIServer CR via `kube` crate `DynamicObject`
- **Cloud managed**: Platform-specific TLS policy API
- **Config file**: Read from environment or mounted config

### Watch and hot-reload

Platform-governed services must watch the TLS profile rather than reading it once at startup — administrators can change it at any time. The pattern is the same for every backend: rebuild the acceptor from the new profile and distribute it via `tokio::sync::watch` (or `ArcSwap`); the accept loop loads the current acceptor per connection. New connections pick up the latest config; existing connections continue with their handshake config. No listener restart needed.

- `openssl` crate — rebuild `SslAcceptor` (as in `build_ssl_context` above) and swap it
- `native-tls` — rebuild `native_tls::TlsAcceptor` from the profile-derived builder and swap it
- `rustls` — rebuild `Arc<ServerConfig>` and swap it

## Key constraints

- For FIPS compliance, use the `openssl` crate (system OpenSSL), not `rustls`
- OpenSSL cipher names match platform APIs directly — no conversion needed
- TLS 1.3 ciphers are always enabled by OpenSSL and not configurable via `set_cipher_list`
- Never use `danger_accept_invalid_certs(true)` in reqwest or equivalent

## Version thresholds

| Version | Capability |
|---|---|
| OpenSSL 3.5+ | ML-KEM (X25519MLKEM768) support |
| rustls 0.23.27+ | ML-KEM support (via aws-lc-rs backend) |
