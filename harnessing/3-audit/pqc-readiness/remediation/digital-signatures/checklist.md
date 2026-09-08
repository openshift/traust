# Post-Quantum Digital Signatures — Master Checklist

## Status
actionable

## Principle
The fix for quantum-vulnerable signatures is **crypto agility**: code should never hardcode a signing algorithm. Make the algorithm configurable so it inherits from platform/runtime defaults. When the ecosystem ships PQ signature support, agile code adopts it without further changes.

## When to apply
- Finding has `pqc_classification: shor-signature` or `clock-2030-parameter`
- Finding cites hardcoded RSA, DSA, ECDSA, EdDSA, RS256/ES256/PS256
- Finding context includes `certificate`, `code-signing`, `jwt`, `sa-token`, or `artifact-signing`

## Anti-patterns (what to detect)
- Hardcoded `jwt.SigningMethodRS256`, `algorithm="RS256"`, `x509.SHA256WithRSA`
- Signature algorithm selected by literal string/constant rather than config
- Verifier rejects unknown `alg` values instead of validating against an allowlist
- Single signing key with no `kid` rotation mechanism
- Code generates keys with hardcoded algorithm (`rsa.GenerateKey`, `ecdsa.GenerateKey`) instead of configurable key type

## Fix principle
1. **Signing**: load algorithm from config/env/platform, not source code
2. **Verification**: accept multiple `alg` during transition; validate `alg` matches key type against an allowlist
3. **Key management**: support `kid` rotation; serve multiple keys via JWKS or trust store
4. **Do not remove classical verification** — relying parties must support PQ before you drop classical

## Detection

```bash
# Go
rg -n 'SigningMethod(RS|ES|PS|Ed)' '**/*.go'
rg -n 'x509\.(SHA256WithRSA|ECDSAWithSHA|PureEd25519)' '**/*.go'
rg -n 'jwt\.Sign|crypto\.Sign' '**/*.go'

# Python
rg -n 'algorithm\s*=\s*["\x27](RS|ES|PS|Ed)' '**/*.py'
rg -n 'jwt\.encode.*algorithm' '**/*.py'

# Java
rg -n 'Signature\.getInstance|Algorithm\.(RSA|EC|Ed)' '**/*.java'

# Rust
rg -n 'Algorithm::(RS|ES|PS|Ed)' '**/*.rs'
rg -n 'EncodingKey::from_rsa|from_ec' '**/*.rs'

# Node.js
rg -n "algorithm.*['\"]RS|ES|PS|Ed" '**/*.{js,ts}'

# CI/CD signing
rg -n 'cosign sign|gpg --sign|rpmsign|notation sign' \
  --glob '*.{yaml,yml,sh,Makefile,Dockerfile*}'
```

## Canonical fix shapes

### JWT / token signing — make algorithm configurable

```go
// BEFORE — hardcoded
token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

// AFTER — algorithm from config; supports rotation to PQ when available
method := jwt.GetSigningMethod(cfg.SigningAlgorithm)
token := jwt.NewWithClaims(method, claims)
```

```python
# BEFORE
encoded = jwt.encode(payload, key, algorithm="RS256")

# AFTER
encoded = jwt.encode(payload, key, algorithm=config.signing_algorithm)
```

### JWT verification — allowlist, not hardcoded expectation

```go
// BEFORE — rejects anything that isn't RS256
token, err := jwt.Parse(tokenString, keyFunc,
    jwt.WithValidMethods([]string{"RS256"}))

// AFTER — allowlist includes classical + future PQ
token, err := jwt.Parse(tokenString, keyFunc,
    jwt.WithValidMethods(cfg.AllowedSigningMethods))
```

### X.509 / certificate issuance — algorithm from config

```go
// BEFORE
template.SignatureAlgorithm = x509.SHA256WithRSA

// AFTER — driven by key type and config
template.SignatureAlgorithm = sigAlgorithmForKey(signerKey)
```

### Code/artifact signing — pass algorithm via pipeline config

```yaml
# BEFORE — hardcoded in CI
- run: cosign sign --key cosign.key $IMAGE

# AFTER — algorithm configurable; defaults to what cosign/runtime supports
- run: cosign sign --key cosign.key --signing-algorithm $SIGNING_ALG $IMAGE
```

## Key constraints
- All classical asymmetric signature algorithms are Shor-vulnerable: RSA, DSA, ECDSA, EdDSA/Ed25519
- HS256/HS384/HS512 are symmetric (Grover-relevant, not Shor) — different remediation path
- ML-DSA signatures are ~3.3 KB; SLH-DSA 8-50 KB — plan for payload/header size impacts when PQ arrives
- Dual-sign during transition: never reject artifacts with only classical sig until PQ verifiers are universal
- Sigstore keyless = sig + Fulcio cert + Rekor proof — all layers must be agile independently
- Crypto agility refactoring is always safe to ship — it changes configuration plumbing, not the algorithm in use today
