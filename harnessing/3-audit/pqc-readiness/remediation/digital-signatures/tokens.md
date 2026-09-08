# Token Signing (JWT, Kubernetes SA, OIDC) — Crypto Agility

## Status
actionable

## Principle
Token signing code should load algorithm from configuration and verifiers should accept an allowlist of algorithms. The runtime's JWT/JOSE library handles PQ algorithms when it supports them — the application code should not be the bottleneck.

## When to apply
- Hardcoded `jwt.SigningMethodRS256`, `algorithm="RS256"`, `Algorithm.RSA256`
- Token verifier rejects unknown `alg` values instead of checking an allowlist
- No `kid` rotation mechanism on signing keys
- `pqc_classification: shor-signature` on auth/token code

## Anti-patterns

```go
// Hardcoded signing method
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
```

```go
// Verifier pinned to single algorithm
jwt.Parse(tokenStr, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
```

```python
# Hardcoded
encoded = jwt.encode(payload, key, algorithm="RS256")
```

```javascript
// Hardcoded
const token = jwt.sign(payload, key, { algorithm: 'RS256' });
```

## Fix patterns

### Signing — algorithm from config

```go
// Algorithm loaded from config; changes with key rotation, no code change needed
method := jwt.GetSigningMethod(cfg.TokenSigningAlgorithm)
if method == nil {
    return fmt.Errorf("unsupported signing method: %s", cfg.TokenSigningAlgorithm)
}
token := jwt.NewWithClaims(method, claims)
```

```python
encoded = jwt.encode(payload, key, algorithm=config.token_signing_algorithm)
```

### Verification — allowlist from config

```go
// Accepts any algorithm in the configured allowlist
token, err := jwt.Parse(tokenStr, keyFunc,
    jwt.WithValidMethods(cfg.AllowedTokenAlgorithms))
```

```python
decoded = jwt.decode(
    token_str,
    key,
    algorithms=config.allowed_token_algorithms,  # ["RS256", "ES256", ...]
)
```

### JWKS / key rotation readiness

```go
// Serve multiple keys with kid — enables algorithm rotation without downtime
type KeySet struct {
    Keys []KeyEntry
}
type KeyEntry struct {
    Kid       string
    Algorithm string
    Key       crypto.Signer
}
```

## Detection

```bash
rg -n 'SigningMethod(RS|ES|PS|Ed)|SigningMethodRS256' '**/*.go'
rg -n 'WithValidMethods.*\[.*"(RS|ES|PS)' '**/*.go'
rg -n 'algorithm\s*=\s*["\x27](RS|ES|PS)' '**/*.py'
rg -n "algorithm.*['\"]RS|ES|PS" '**/*.{js,ts}'
rg -n 'Algorithm\.(RSA|EC|Ed)' '**/*.java'
```

## Key constraints
- All classical JOSE asymmetric algs are Shor-vulnerable: RS256/384/512, PS256/384/512, ES256/384/512, EdDSA
- HS256/HS384/HS512 are symmetric (Grover-relevant, not Shor) — different path, lower priority
- JWT in `Authorization: Bearer`: PQ tokens will be ~4-5 KB — may exceed reverse proxy header limits; plan header size budget
- Kubernetes SA tokens: the kube-apiserver signs these; platform-level fix, but application token code should still be agile
- Crypto agility refactoring is safe to ship immediately — it changes plumbing, not the active algorithm
