# TLS Server Key Exchange — Python

## Status
actionable

## When to apply
- Finding cites missing or hardcoded TLS config in a Python service
- TLS version pinned below platform profile
- No mechanism to read or honor a platform-wide TLS security profile
- Missing certificate validation

## Approach selection

| Scenario | Approach |
|---|---|
| Service consuming a platform TLS profile | Read profile from platform API → build `ssl.SSLContext` |
| Standalone Python service | Use default `ssl.SSLContext`; ensure OpenSSL 3.5+ for ML-KEM |
| Framework: Flask/FastAPI/uvicorn/aiohttp | Same fetch, pass SSLContext to server |

## Canonical fix patterns

### Standalone service — OpenSSL 3.5+ defaults

With OpenSSL 3.5+, `X25519MLKEM768` is negotiated by default. No Python code changes needed beyond ensuring the linked OpenSSL version.

```python
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(certfile, keyfile)
```

### Platform-governed service — read TLS config from platform

```python
import ssl
from typing import Any


def build_ssl_context(
    spec: dict[str, Any],
    certfile: str,
    keyfile: str,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = parse_tls_version(spec["minTLSVersion"])

    if spec.get("ciphers") and ctx.minimum_version < ssl.TLSVersion.TLSv1_3:
        ctx.set_ciphers(":".join(spec["ciphers"]))

    ctx.load_cert_chain(certfile, keyfile)
    return ctx
```

The profile source depends on your platform:
- **OCP**: APIServer CR (`apiservers.config.openshift.io/cluster`) via kubernetes client
- **Cloud managed**: Platform-specific TLS policy API
- **Config file**: Read from environment or mounted config

### Watch for profile changes

Platform-governed services must watch the TLS profile rather than reading it once at startup — administrators can change it at any time. When the watch reports a change:

1. **Servers that wrap per-connection** (most accept loops, `asyncio` TLS) — rebuild the `SSLContext` from the new profile and atomically swap the reference the accept path uses; every new connection wraps with the fresh context, no restart.
2. **Per-handshake swap** — `SSLContext.sni_callback` runs on every handshake and may reassign `sslobject.context` to the current profile-derived context; this is Python's closest analog of Go's `GetConfigForClient`.
3. **Frameworks that bake the context at bind time** (gunicorn/uvicorn `--ssl-*` workers) — the context cannot be swapped in place; trigger a graceful worker recycle (e.g. SIGHUP) on profile change so replacement workers bind with the new config.

## Key constraints

- Python's `ssl` module uses OpenSSL under the hood — cipher names match directly
- PQC (ML-KEM) support depends on the underlying OpenSSL version (>= 3.5)
- `TLSv1` and `TLSv1.1` are deprecated in Python 3.10+ and disabled in OpenSSL 3.0+
- Watch the profile for changes rather than reading once at startup

## Version thresholds

| Version | Capability |
|---|---|
| OpenSSL 3.5+ | ML-KEM (X25519MLKEM768) support |
| Python 3.12+ with OpenSSL 3.5 | ML-KEM available via ssl module |
| Python 3.15+ | `SSLContext.set_groups()` for explicit group configuration |
| Python 3.10+ | TLSv1/TLSv1.1 deprecated |
