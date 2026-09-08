# X.509 Certificate Signing — Crypto Agility

## Status
actionable

## Principle
Certificate issuance code should derive its `SignatureAlgorithm` from the signing key's type, not a hardcoded constant. When the platform gains PQ key support, agile cert code issues PQ-signed certs without source changes.

## When to apply
- Hardcoded `x509.SHA256WithRSA`, `ECDSAWithSHA256`, `Ed25519` in cert generation
- CA/leaf cert, CSR signing, OCSP responder, CRL signing with pinned algorithm
- cert-manager or OpenShift serving cert configs with fixed algorithm

## Anti-pattern

```go
// Hardcoded — must change source to adopt new algorithm
template := &x509.Certificate{
    SignatureAlgorithm: x509.SHA256WithRSA,
    // ...
}
```

```python
# Hardcoded
cert = x509.CertificateBuilder().sign(key, hashes.SHA256())
```

## Fix pattern

```go
// Derive from key type — automatically uses correct algorithm for any key
func signatureAlgorithmForKey(key crypto.Signer) x509.SignatureAlgorithm {
    switch k := key.Public().(type) {
    case *rsa.PublicKey:
        return x509.SHA256WithRSA
    case *ecdsa.PublicKey:
        // curve-appropriate hash
    case ed25519.PublicKey:
        return x509.PureEd25519
    default:
        // future: ML-DSA keys will map to their OID automatically
        return x509.UnknownSignatureAlgorithm
    }
}

template.SignatureAlgorithm = signatureAlgorithmForKey(caKey)
```

```python
# Derive from key — padding/hash selected per key type
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


def sign_cert(builder, ca_key):
    if isinstance(ca_key, rsa.RSAPrivateKey):
        return builder.sign(ca_key, hashes.SHA256(), padding.PKCS1v15())
    elif isinstance(ca_key, ec.EllipticCurvePrivateKey):
        return builder.sign(ca_key, hashes.SHA256())
    # future: ML-DSA keys will be handled by cryptography lib
    return builder.sign(ca_key, None)
```

## Detection

```bash
rg -n 'SignatureAlgorithm.*=' '**/*.go' | rg -v 'func|switch|case|//'
rg -n 'x509\.(SHA|ECDSA|PureEd)' '**/*.go'
rg -n '\.sign\(.*hashes\.' '**/*.py'
rg -n 'Signature\.getInstance' '**/*.java'
```

## Key constraints
- `x509.CreateCertificate` in Go infers algorithm from key when `SignatureAlgorithm == 0` — omitting the field IS the agile fix for simple cases
- OCSP responses and CRLs inherit issuer signature algorithm — agility propagates through the chain
- ML-DSA keys MUST NOT have `keyEncipherment`/`keyAgreement` in `keyUsage` (RFC 9881)
- Size: ML-DSA-65 cert ~5-8 KB vs ~1 KB ECDSA P-256 — plan for CT log / wire impacts
