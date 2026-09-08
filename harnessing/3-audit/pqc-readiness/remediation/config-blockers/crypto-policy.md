# System-Level Crypto Policies That Block PQC

## Status
actionable

## When to apply
- RHEL/Fedora/UBI host or container where OpenSSL/NSS/GnuTLS-backed TLS is used
- `update-crypto-policies --show` returns policy without PQ on RHEL 9.7+
- Container image pins old `crypto-policies` package predating PQ module
- Application overrides system policy via custom `OPENSSL_CONF` or back-end removal

## Anti-patterns (BEFORE — what to detect and remove)

### RHEL 9.7+ — failure to opt in to PQ module

```bash
# update-crypto-policies --show
DEFAULT   # without :PQ suffix
FIPS      # without :PQ suffix
```

**Why it blocks PQC:** RHEL 9.7 introduced `PQ` as opt-in. Without `:PQ`, ML-KEM groups are absent.

### RHEL 10.1+ — explicit NO-PQ subpolicy

```bash
DEFAULT:NO-PQ
```

**Why it blocks PQC:** RHEL 10.1 enables PQC by default; `NO-PQ` strips it.

### Custom policy excluding PQ groups

```ini
# /etc/crypto-policies/policies/MYPOLICY.pol
group = X25519 SECP256R1 SECP384R1 SECP521R1 FFDHE2048
```

### OPENSSL_CONF group restriction

```ini
[system_default_sect]
Groups = X25519:P-256:P-384
```

### Container base image — stale crypto-policies

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.2
# No update-crypto-policies; uses image-baked classical-only policy
```

## Fix patterns (AFTER — the remediation)

### RHEL 9.7+ — enable PQ subpolicy

```bash
update-crypto-policies --set DEFAULT:PQ
# or
update-crypto-policies --set FIPS:PQ

# Verify
grep -i mlkem /etc/crypto-policies/state/CURRENT.pol
```

### RHEL 10.1+ — remove NO-PQ if present

```bash
update-crypto-policies --set DEFAULT
# PQ is on by default
```

### Container — rebuild with current policy

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7
RUN microdnf install -y crypto-policies-scripts && \
    update-crypto-policies --set DEFAULT:PQ && \
    microdnf clean all
```

### Remove OPENSSL_CONF override

```bash
unset OPENSSL_CONF
# Let crypto-policies back-end apply
```

## Detection

```bash
update-crypto-policies --show 2>/dev/null || \
  cat /etc/crypto-policies/state/CURRENT 2>/dev/null

grep -E '^group\s*=' /etc/crypto-policies/state/CURRENT.pol

rg -n 'update-crypto-policies|NO-PQ|:PQ' \
  --glob '*.{sh,yml,yaml,Dockerfile*,tf,mco}'

rg -n 'OPENSSL_CONF' --glob '*.{yaml,yml,env,sh,Dockerfile*}'
```

## Key constraints
- **Scope:** crypto-policies govern OpenSSL, NSS, GnuTLS, OpenSSH apps. **Upstream Go `crypto/tls` does NOT read crypto-policies.**
- Changing node policy on container platforms may require platform-specific mechanisms (e.g. MachineConfig on OCP)
- `update-crypto-policies` requires root and service restarts
- Container pods carry their own `/etc/crypto-policies` unless sharing host policy
- `FUTURE`/`LEGACY` base policies accept `:PQ` on RHEL 9.7+

## Platform behavior (determines which fix shape to apply)

| OS | PQ default? | Enable command |
|---|---|---|
| RHEL 9.0-9.6 | No | Upgrade to 9.7+ |
| RHEL 9.7+ | No (opt-in) | `update-crypto-policies --set DEFAULT:PQ` |
| RHEL 10.0 | No (TP) | `DEFAULT:TEST-PQ` |
| RHEL 10.1+ | **Yes** | Remove `NO-PQ` if set |

## FIPS interaction
- **RHEL 9.7 `FIPS:PQ`:** hybrid ML-KEM works in FIPS mode for OpenSSL-backed components
- **OpenSSL FIPS provider:** NIST-curve hybrids (`SecP256r1MLKEM768`) work; `X25519MLKEM768` is NOT in FIPS provider
- **`FIPS` without `:PQ`:** classical groups only — PQ blocker
- **FIPS clusters:** node-level `FIPS:PQ` affects OpenSSL pods; Go services need separate Go-level fixes

## Evidence
- [RHEL 9 crypto-policies](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening) — PQ subpolicy
- [RHEL 10 crypto-policies](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/using-system-wide-cryptographic-policies) — PQC default
- [RHEL 10.1 PQC blog](https://www.redhat.com/en/blog/whats-new-post-quantum-cryptography-rhel-101)
- [RHEL 9.7 PQC blog](https://www.redhat.com/en/blog/prepare-post-quantum-future-rhel-97)
- [RHEL PQC interoperability](https://access.redhat.com/articles/7119430)
- [crypto-policies(7)](https://www.mankier.com/7/crypto-policies) — "Go does not yet follow system-wide policy"
