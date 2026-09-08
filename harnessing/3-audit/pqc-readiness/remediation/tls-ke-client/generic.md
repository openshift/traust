# TLS Client Key Exchange — Generic (Non-Go)

## Status
actionable

## When to apply
- Outbound TLS client pins classical-only key exchange groups
- Client TLS version capped below 1.3
- Custom TLS context copied from server hardening guides applied to clients
- Finding cites `tls-client`, `http-client`, `grpc-client`, or `db-client` with `pqc-blocker-config`
- Language is not Go (Python, Node.js, Rust, Java, etc.)

Principle: **clients must not restrict TLS negotiation**. ML-KEM hybrid key exchange is negotiated via TLS 1.3 supported groups. Let the TLS library defaults work unless you have a documented interoperability reason to override.

## Approach selection

| Language / stack | Fix pattern |
|---|---|
| Python (`requests`, `httpx`, `aiohttp`) | Use default `ssl.create_default_context()`; do not call `set_groups()` with classical-only list; do not cap `maximum_version` |
| Node.js (`https`, `fetch`, `axios`) | Do not set `maxVersion: 'TLSv1.2'`; do not pin `ecdhCurve` to classical-only |
| Rust (`reqwest` + rustls) | Do not restrict `ClientConfig` KX groups; use crate defaults |
| Rust (`reqwest` + native-tls/OpenSSL) | Depends on system OpenSSL >= 3.5; do not pin groups |
| Java (`HttpClient`, OkHttp, gRPC-Java) | Do not call `SSLParameters.setNamedGroups()` with classical-only list |
| Ruby (`Net::HTTP`, Faraday) | Fix base image OpenSSL; remove explicit protocol/group pins |

## Canonical fix pattern

### Universal principle

```
BEFORE (anti-pattern):
  - Pin supported groups/curves to classical-only (X25519, P-256, P-384)
  - Cap maximum TLS version at 1.2
  - Copy server-side hardening (cipher lists, group lists) onto outbound clients

AFTER (fix):
  - Configure trust only: CA bundle, SNI/server name, optional client certificate
  - Leave group/KX negotiation to library defaults
  - Ensure runtime OpenSSL/JDK/rustls version supports ML-KEM
  - Remove explicit classical-only group/version restrictions
```

### Python — requests / httpx

```python
# BEFORE — blocks ML-KEM
import ssl
import httpx

ctx = ssl.create_default_context()
ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # blocks TLS 1.3

# AFTER — trust only
import ssl
import httpx

ctx = ssl.create_default_context(cafile="/etc/ssl/certs/ca-bundle.crt")
client = httpx.Client(verify=ctx)
```

PQC capability depends on the **system or bundled OpenSSL**, not Python version alone.

### Node.js — https / fetch / axios

```javascript
// BEFORE — caps TLS 1.3; blocks ML-KEM
const agent = new https.Agent({
    ca: fs.readFileSync("ca.pem"),
    maxVersion: "TLSv1.2",
    ecdhCurve: "X25519",
});

// AFTER — trust only
const agent = new https.Agent({
    ca: fs.readFileSync("ca.pem"),
    minVersion: "TLSv1.2",
});
```

### Rust — reqwest (rustls)

```rust
// BEFORE — classical-only KX groups
let mut provider = default_provider();
provider.kx_groups = vec![
    &rustls::crypto::aws_lc_rs::kx_group::X25519,
    &rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
];
provider.install_default().unwrap();

// AFTER — use defaults (X25519MLKEM768 available with aws-lc-rs)
let client = Client::builder()
    .use_rustls_tls()
    .build()?;
```

### Java — HttpClient

```java
// BEFORE — classical-only named groups
SSLParameters params = sslSocket.getSSLParameters();
params.setNamedGroups(new String[] { "x25519", "secp256r1" });

// AFTER — do not override named groups; JDK defaults apply
HttpClient client = HttpClient.newBuilder()
    .sslContext(sslContext)
    .build();
```

Also check JVM flags: `-Djdk.tls.namedGroups=...` with classical-only values.

## Key constraints

- ML-KEM hybrid key exchange is a TLS 1.3 **named group**, not a cipher suite
- Pinning cipher suites (TLS 1.2) does not enable PQC; capping TLS version at 1.2 blocks it
- The fix is usually **removing** explicit restrictions, not adding PQC configuration
- Trust configuration (CA bundle, SNI, client certs) is always appropriate
- Never disable certificate verification (`verify=False`, `rejectUnauthorized: false`, etc.)
- Runtime library version matters as much as application code
- Infrastructure-governed clients: fixing the client removes the blocker; server must also offer ML-KEM

## Version thresholds

| Runtime | ML-KEM client capability |
|---|---|
| OpenSSL 3.5+ | `X25519MLKEM768` in default TLS 1.3 groups |
| OpenSSL 3.0–3.4 | No ML-KEM; classical ECDHE only |
| Python any + OpenSSL 3.5+ | `ssl` module inherits OpenSSL PQC defaults |
| Node.js 22+ | Bundled OpenSSL 3.5+ -> ML-KEM negotiated by default |
| Node.js 20 LTS | Bundled OpenSSL 3.0.x -> no ML-KEM |
| rustls 0.23.22+ (aws-lc-rs) | `X25519MLKEM768` available |
| JDK 24 | ML-KEM in `javax.crypto` (JEP 496) — not TLS key exchange |
| JDK 27+ (JEP 527) | TLS 1.3 hybrid groups in JSSE |

## Evidence

- [OpenSSL 3.5 groups](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/) — ML-KEM hybrid in default group list
- [JEP 527 / JDK 27](https://inside.java/2026/02/17/tls-post-quantum-hybrid-key-exchange/) — hybrid groups in JSSE
- [JEP 496 / JDK 24](https://openjdk.org/jeps/496) — ML-KEM crypto API (not TLS)
- [rustls 0.23.22](https://github.com/rustls/rustls/releases/tag/v%2F0.23.22) — X25519MLKEM768 support
- [Node.js PQC TLS](https://dev.to/daan_acohen/is-your-nodejs-app-quantum-safe-tracing-pqc-in-tls-connections-10b8) — Node 22+ negotiates ML-KEM
