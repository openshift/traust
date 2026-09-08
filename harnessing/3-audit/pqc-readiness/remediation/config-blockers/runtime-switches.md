# Runtime Switches That Disable PQC

## Status
actionable

## Principle
Every major TLS runtime has deployment-level knobs (environment variables, system properties, registry keys, config files) that override library defaults to disable PQC. The fix is always: **remove the override and let the runtime's built-in defaults negotiate PQC.** These are distinct from source-code group pins (see `curve-pins.md`) — they're operational configs applied outside the application code.

## When to apply
- Finding flags `pqc-blocker-config` with evidence of a runtime switch disabling PQC
- TLS handshake negotiates only classical groups despite runtime version supporting PQC
- Deployment manifests, Dockerfiles, systemd units, JVM args, or registry keys cap TLS or disable PQ features

---

## Go — GODEBUG

### Anti-patterns

```dockerfile
ENV GODEBUG=tlsmlkem=0
```

```yaml
env:
  - name: GODEBUG
    value: "tlsmlkem=0"
```

```go
// go.mod
godebug (
    tlsmlkem=0
)
```

```go
//go:debug tlsmlkem=0
package main
```

```go
// Old go directive inherits pre-PQC defaults
go 1.20
```

```go
func init() {
    os.Setenv("GODEBUG", "tlsmlkem=0")
}
```

**Why it blocks PQC:** `tlsmlkem=0` restores pre-Go 1.24 curve list, excluding all ML-KEM hybrids. Old `go` directive in go.mod bakes pre-1.24 GODEBUG defaults into the binary.

### Fix

```dockerfile
# Remove GODEBUG line or strip tlsmlkem from compound value
```

```go
// Bump go directive; remove godebug block
go 1.24
```

```bash
# Verify
go list -f '{{.DefaultGODEBUG}}' ./cmd/myapp
# Should NOT contain tlsmlkem=0
```

### Detection

```bash
rg -n 'tlsmlkem\s*=\s*0|tlskyber\s*=\s*0' \
  --glob '*.{yaml,yml,json,env,sh,Dockerfile*,containerfile*}'
rg -n 'godebug|//go:debug|tlsmlkem' go.mod go.work '**/*.go'
rg -n 'Setenv\s*\(\s*"GODEBUG"' '**/*.go'
```

---

## Java/JVM — Security Properties and System Properties

### Anti-patterns

```bash
# JVM argument — restricts named groups to classical-only
java -Djdk.tls.namedGroups="secp256r1,secp384r1,x25519" -jar app.jar
```

```ini
# $JAVA_HOME/conf/security/java.security — classical-only groups
jdk.tls.namedGroups=secp256r1,secp384r1,x25519
```

```bash
# Cap TLS version — blocks TLS 1.3 (required for ML-KEM)
java -Djdk.tls.client.protocols="TLSv1.2" -jar app.jar
```

```ini
# java.security — disable TLS 1.3
jdk.tls.disabledAlgorithms=TLSv1.3
```

```bash
# JAVA_TOOL_OPTIONS / _JAVA_OPTIONS — same effect, hidden in env
JAVA_TOOL_OPTIONS="-Djdk.tls.namedGroups=secp256r1,secp384r1"
```

**Why it blocks PQC:** JDK's TLS implementation respects `jdk.tls.namedGroups` as an allowlist. If ML-KEM hybrids aren't listed, they won't be offered. `jdk.tls.client.protocols=TLSv1.2` prevents TLS 1.3 entirely.

### Fix

```bash
# Remove the system property — let JDK defaults include PQ groups
java -jar app.jar
# Or explicitly include PQ group when curation required:
java -Djdk.tls.namedGroups="ML-KEM-768,x25519,secp256r1" -jar app.jar
```

```ini
# java.security — remove namedGroups restriction or include PQ
# jdk.tls.namedGroups=  (comment out / delete)
```

### Detection

```bash
rg -n 'jdk\.tls\.namedGroups|jdk\.tls\.client\.protocols|jdk\.tls\.disabledAlgorithms' \
  --glob '*.{properties,conf,xml,yaml,yml,sh,Dockerfile*,env}'
rg -n 'JAVA_TOOL_OPTIONS|_JAVA_OPTIONS' \
  --glob '*.{yaml,yml,env,sh,Dockerfile*,service}'
rg -n 'Djdk\.tls' --glob '*.{sh,yaml,yml,Dockerfile*,xml,gradle,properties}'
```

---

## Node.js — CLI Flags and Environment Variables

### Anti-patterns

```bash
# Cap TLS version — blocks TLS 1.3 key exchange
node --tls-max-v1.2 server.js
```

```bash
# Via NODE_OPTIONS env
NODE_OPTIONS="--tls-max-v1.2"
```

```bash
# Force specific OpenSSL cipher/group config via env
OPENSSL_CONF=/etc/ssl/classical-only.cnf node server.js
```

```yaml
# Kubernetes deployment
env:
  - name: NODE_OPTIONS
    value: "--tls-max-v1.2"
```

**Why it blocks PQC:** `--tls-max-v1.2` prevents TLS 1.3 negotiation entirely. `OPENSSL_CONF` can override the group list Node.js passes to OpenSSL.

### Fix

```bash
# Remove the flag — Node.js defaults to TLS 1.3 max
node server.js
```

```yaml
# Remove NODE_OPTIONS TLS cap from deployment
env: []
```

### Detection

```bash
rg -n 'tls-max-v1\.2|tls-max-v1\.1' \
  --glob '*.{yaml,yml,sh,Dockerfile*,env,json}'
rg -n 'NODE_OPTIONS.*tls' --glob '*.{yaml,yml,env,sh,Dockerfile*}'
rg -n 'OPENSSL_CONF' --glob '*.{yaml,yml,env,sh,Dockerfile*}'
```

---

## Python — SSLContext Protocol Caps

### Anti-patterns

```python
# Caps max TLS version — blocks TLS 1.3 negotiation
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
```

```python
# Legacy protocol constant — TLS 1.2 only
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
```

```bash
# Environment override (OpenSSL-backed)
OPENSSL_CONF=/path/to/classical.cnf python app.py
```

**Why it blocks PQC:** `maximum_version = TLSv1_2` prevents TLS 1.3 handshake. ML-KEM hybrids are TLS 1.3 only. The legacy `PROTOCOL_TLSv1_2` constant forces that version exclusively.

### Fix

```python
# Use create_default_context() — inherits runtime OpenSSL defaults
ctx = ssl.create_default_context()
# maximum_version intentionally unset — allows TLS 1.3
```

### Detection

```bash
rg -n 'maximum_version.*TLSv1_2|PROTOCOL_TLSv1_2|PROTOCOL_TLSv1_1' '**/*.py'
rg -n 'OPENSSL_CONF' --glob '*.{yaml,yml,env,sh,Dockerfile*}'
```

---

## Rust — Feature Flags and Provider Config

### Anti-patterns

```toml
# Cargo.toml — disables PQ feature
[dependencies]
rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }
# Missing: "prefer-post-quantum" feature (enabled by default)
```

```rust
// Custom CryptoProvider without PQ — overrides default
let provider = CryptoProvider {
    kx_groups: vec![&aws_lc_rs::kx_group::X25519],
    ..aws_lc_rs::default_provider()
};
rustls::ClientConfig::builder_with_provider(Arc::new(provider))
```

**Why it blocks PQC:** `default-features = false` without re-enabling `prefer-post-quantum` removes ML-KEM from the negotiation order. Custom `CryptoProvider` with only classical `kx_groups` excludes PQ entirely.

### Fix

```toml
# Use default features (includes prefer-post-quantum)
[dependencies]
rustls = "0.23"
```

```rust
// Use default provider — includes X25519MLKEM768 at highest priority
rustls::ClientConfig::builder_with_provider(
    Arc::new(aws_lc_rs::default_provider())
)
```

### Detection

```bash
rg -n 'default-features\s*=\s*false' --glob 'Cargo.toml' | rg rustls
rg -n 'prefer-post-quantum' --glob 'Cargo.toml'
rg -n 'CryptoProvider\s*\{' '**/*.rs'
```

---

## Windows — Schannel Registry and Group Policy

### Anti-patterns

```reg
; Registry — disables TLS 1.3 (required for ML-KEM)
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client]
"Enabled"=dword:00000000

; Registry — restricts key exchange algorithms
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ML-KEM]
"Enabled"=dword:00000000
```

```powershell
# Group Policy — TLS cipher suite order without PQ
# Computer Configuration > Network > SSL Configuration Settings
# Cipher suite list: TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256
# (no PQ KEM cipher suites)
```

**Why it blocks PQC:** Schannel registry keys are the Windows equivalent of GODEBUG — they override the OS default TLS behavior. Disabling TLS 1.3 or explicitly disabling ML-KEM prevents PQ negotiation for all Schannel-backed apps (.NET, PowerShell, WinHTTP, IIS).

### Fix

```powershell
# Remove the registry override — let Windows defaults apply
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name "Enabled"
```

### Detection

```bash
rg -n 'SCHANNEL|TLS 1\.3.*Enabled|KeyExchangeAlgorithms' \
  --glob '*.{reg,ps1,psm1,inf,admx}'
rg -n 'Disable-TlsCipherSuite|Set-TlsCipherSuite' --glob '*.{ps1,psm1}'
```

---

## Key constraints
- All of these are operational/deployment configs — the fix lives in manifests, Dockerfiles, JVM args, or system config, not application source
- TLS version caps (max TLS 1.2) block ALL PQC since ML-KEM is TLS 1.3 only
- `GODEBUG` is Go-unique; other runtimes use different mechanisms but same principle
- Removing a runtime switch only enables PQC if the underlying crypto library version supports it — the patch agent should check the target's actual runtime version
- If the switch was added as a workaround (handshake timeouts, firewall issues), removing it may resurface that problem — note it in the rationale but still emit the fix

## Detection (cross-ecosystem summary)

```bash
# All runtime PQC kill-switches in one pass
rg -n 'tlsmlkem=0|tls-max-v1\.2|maximum_version.*TLSv1_2|PROTOCOL_TLSv1_2|jdk\.tls\.namedGroups|jdk\.tls\.client\.protocols|SCHANNEL.*TLS 1\.3|prefer-post-quantum' \
  --glob '*.{go,py,java,js,ts,rs,toml,yaml,yml,sh,env,Dockerfile*,properties,conf,reg,ps1}'
```
