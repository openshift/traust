# TLS Server Key Exchange — Node.js / TypeScript

## Status
actionable

## When to apply
- Finding cites missing or hardcoded TLS config in a Node.js/TypeScript service
- TLS version pinned below platform profile
- No mechanism to read or honor a platform-wide TLS security profile
- Missing certificate validation or `rejectUnauthorized: false`

## Approach selection

| Scenario | Approach |
|---|---|
| Service consuming a platform TLS profile | Read profile from platform API → `SecureContextOptions` |
| Standalone Node.js service | Use default TLS options; ensure OpenSSL 3.5+ for ML-KEM |
| Express/Fastify/Koa | Same fetch, pass options to `https.createServer` |
| Hot-reload capable | `server.setSecureContext()` on profile change (no restart) |

## Canonical fix patterns

### Standalone service — OpenSSL 3.5+ defaults

```ts
import https from "node:https";
import { readFileSync } from "node:fs";

const server = https.createServer(
  {
    cert: readFileSync("certs/tls.crt"),
    key: readFileSync("certs/tls.key"),
    minVersion: "TLSv1.2",
  },
  (req, res) => {
    res.writeHead(200);
    res.end("ok");
  },
);
server.listen(8443);
```

### Platform-governed service — read TLS config from platform

```ts
import type { SecureContextOptions } from "tls";

interface TLSProfileSpec {
  minTLSVersion: string;
  ciphers: string[];
}

function toSecureContextOptions(spec: TLSProfileSpec): SecureContextOptions {
  const minVersion = VERSION_MAP[spec.minTLSVersion] ?? "TLSv1.2";
  if (minVersion === "TLSv1.3") {
    return { minVersion };
  }
  return { minVersion, ciphers: spec.ciphers.join(":") };
}
```

The profile source depends on your platform:
- **OCP**: APIServer CR via `@kubernetes/client-node`
- **Cloud managed**: Platform-specific TLS policy API
- **Config file**: Read from environment or mounted config

### Watch for profile changes and hot reload

Platform-governed services must watch the TLS profile rather than reading it once at startup — administrators can change it at any time. On change, `setSecureContext()` swaps TLS options on a live server — no restart, new handshakes pick up the updated config immediately.

```ts
profileWatcher.on("change", (profile) => {
  server.setSecureContext({ ...toTlsOptions(profile), cert, key });
});
```

## Key constraints

- Node.js uses OpenSSL under the hood — cipher names match directly
- `setSecureContext()` enables hot reload without server restart
- Never set `rejectUnauthorized: false`
- PQC (ML-KEM) support depends on the underlying OpenSSL version (>= 3.5)

## Version thresholds

| Version | Capability |
|---|---|
| Node.js 22+ with OpenSSL 3.5 | ML-KEM (X25519MLKEM768) available |
| Node.js 20 LTS | No ML-KEM (OpenSSL 3.0.x) |
| OpenSSL 3.5+ | ML-KEM groups in TLS 1.3 |
