# Code and Artifact Signing — Crypto Agility

## Status
actionable

## Principle
Signing pipelines should pass algorithm as configuration, not embed it in source. The signing tool (cosign, notation, rpmsign, gpg) inherits from the key type and runtime crypto defaults. Pipeline code should not restrict which algorithms the tool can use.

## When to apply
- Hardcoded ECDSA P-256 / RSA-2048 / Ed25519 in CI/CD signing steps
- `pqc_classification: shor-signature` on supply-chain or artifact signing code
- Signing key type baked into pipeline with no rotation mechanism

## Anti-pattern

```yaml
# CI pipeline — hardcoded key type assumption
- run: |
    cosign generate-key-pair --kms awskms:///alias/signing
    cosign sign --key awskms:///alias/signing $IMAGE
```

```python
# Signing library — hardcoded algorithm
signer = Signer(key, algorithm="ecdsa-sha256")
attestation = signer.sign(payload)
```

## Fix pattern

```yaml
# CI pipeline — algorithm from config; tool uses key's native algorithm
- run: |
    cosign sign --key $SIGNING_KEY_REF \
      ${SIGNING_ALG:+--signing-algorithm $SIGNING_ALG} \
      $IMAGE
  env:
    SIGNING_KEY_REF: ${{ vars.SIGNING_KEY_REF }}
    SIGNING_ALG: ${{ vars.SIGNING_ALGORITHM }}  # empty = tool default
```

```python
# Signing library — algorithm derived from key, not hardcoded
signer = Signer(key)  # algorithm inferred from key type
attestation = signer.sign(payload)
```

### Verification — accept multiple algorithms

```python
# BEFORE — rejects non-ECDSA signatures
verifier = Verifier(pub_key, algorithm="ecdsa-sha256")

# AFTER — algorithm inferred from key; allowlist for trust boundary
verifier = Verifier(pub_key)  # accepts whatever the key's algorithm is
```

## Detection

```bash
rg -n 'cosign sign|notation sign|gpg --sign|rpmsign' \
  --glob '*.{yaml,yml,sh,Makefile,Dockerfile*,Jenkinsfile}'

rg -n 'algorithm.*ecdsa|algorithm.*rsa|algorithm.*ed25519' \
  --glob '*.{py,go,js,ts,java,rs}'

rg -n 'generate-key-pair|GenerateKey' \
  --glob '*.{yaml,yml,sh,go,py,rs}'
```

## Key constraints
- Dual-sign during transition: attach classical + PQ signatures; verifier accepts either
- Do NOT reject artifacts with only classical sig until PQ verifiers are deployed everywhere
- ML-DSA sigs ~3 KB; SLH-DSA 8-50 KB — unsuitable for high-throughput CI attestations
- Sigstore keyless chain = artifact sig + Fulcio cert + Rekor proof — each layer's algorithm is independent; agility needed at each
