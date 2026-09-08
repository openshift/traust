#!/usr/bin/env python3
"""
build_insecure_patterns.py — cross-portfolio insecure-coding-pattern roll-up.

Walks every *-security-audit.json under <results-root>/findings/ (owned,
Hybrid Platforms) and <results-root>/oss-findings/ (upstream community code
HP depends on), keeps only findings whose evidence/location is *source code*
(drops YAML/JSON/Dockerfile/Helm config-and-manifest gaps), buckets each
occurrence by its primary CWE, maps that CWE to the OWASP ASVS 5.0
chapter/section taxonomy, and emits:

  insecure-patterns.json           machine-readable roll-up
  insecure-patterns-top25.md       ranked table, repo counts, ASVS category
  insecure-patterns-detailed.md    top-50 with example functions + fix
  insecure-patterns-dashboard.html self-contained interactive dashboard

Ranking is by *distinct repository count* (a repo audited on 10 branches
counts once). Occurrences are de-duplicated by (repo, cwe, path) so that
per-branch report copies don't inflate the numbers.

The MAIN ranked tables are OWNED-ONLY (findings/). The upstream tree
(oss-findings/) is aggregated with the same rules but reported as a separate
tagged "Upstream cut" — it is never folded into the owned ranking, repo
counts, or examples.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import html
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from traust_engine.assets import harness_version as engine_harness_version
from traust_engine.corpus.resolver import walk_reports

from traust.context import (
    add_config_home_arg,
    load_engine,
    resolve_results_root,
)
from traust.paths import HARNESS_ROOT

# ─────────────────────────────────────────────────────────────────────────────
# what counts as "source code" vs "config/manifest"
# ─────────────────────────────────────────────────────────────────────────────
CODE_EXT = re.compile(
    r"\.(go|py|ts|tsx|mts|cts|js|jsx|mjs|cjs|java|kt|kts|scala|groovy|"
    r"c|cc|cpp|cxx|h|hh|hpp|rs|rb|php|cs|swift|m|mm|sh|bash|zsh|pl|pm|"
    r"lua|ex|exs|erl|hs|clj|cljs)$",
    re.I,
)
CODE_LANGS = {
    "go",
    "golang",
    "python",
    "py",
    "typescript",
    "ts",
    "tsx",
    "javascript",
    "js",
    "jsx",
    "java",
    "kotlin",
    "scala",
    "groovy",
    "c",
    "cpp",
    "c++",
    "rust",
    "ruby",
    "php",
    "csharp",
    "c#",
    "swift",
    "objc",
    "objective-c",
    "sh",
    "bash",
    "shell",
    "zsh",
    "perl",
    "lua",
    "elixir",
    "erlang",
    "haskell",
    "clojure",
}
# extensions/languages that mark a finding as config-only when they are the
# *only* thing present. (yaml go-templates still count as config.)
CONFIG_EXT = re.compile(
    r"(\.(ya?ml|json|jsonc|toml|ini|cfg|conf|xml|properties|tf|tfvars|hcl|"
    r"tpl|tmpl|env|mk)$|(^|/)(Dockerfile|Containerfile|Makefile|Chart\.yaml|"
    r"values\.ya?ml|kustomization\.ya?ml))",
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# CWE → (name, ASVS 5.0 section id, section name, one/two-line root-cause fix)
# Curated for the CWEs that actually appear in the corpus. Anything not listed
# falls back to a chapter-level mapping via CWE_ASVS_FALLBACK.
# ─────────────────────────────────────────────────────────────────────────────
CWE_META = {
    # ── logging / info exposure ────────────────────────────────────────────
    "CWE-532": (
        "Insertion of Sensitive Information into Log File",
        "V16.2",
        "Security Logging › General Logging",
        "Redact tokens, credentials, presigned URLs and full request/response bodies before logging; log identifiers and hashes, never secret material.",
    ),
    "CWE-200": (
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "V14.2",
        "Data Protection › General Data Protection",
        "Return minimal fields; strip stack traces, internal hostnames and object dumps from responses and errors surfaced to callers.",
    ),
    "CWE-209": (
        "Generation of Error Message Containing Sensitive Information",
        "V16.5",
        "Security Logging › Error Handling",
        "Map internal errors to generic user-facing messages; log detail server-side only.",
    ),
    "CWE-214": (
        "Invocation of Process Using Visible Sensitive Information",
        "V13.3",
        "Configuration › Secret Management",
        "Pass secrets via env or stdin, never argv; scrub `/proc/<pid>/cmdline`-visible flags.",
    ),
    "CWE-312": (
        "Cleartext Storage of Sensitive Information",
        "V14.2",
        "Data Protection › General Data Protection",
        "Encrypt at rest or store a reference to a secrets manager instead of the plaintext value; set restrictive file modes.",
    ),
    "CWE-313": (
        "Cleartext Storage in a File or on Disk",
        "V14.2",
        "Data Protection › General Data Protection",
        "Write secrets only to tmpfs/Secret volumes with 0600 perms, or don't write them at all — read from the secret store on demand.",
    ),
    "CWE-315": (
        "Cleartext Storage of Sensitive Information in a Cookie",
        "V3.3",
        "Web Frontend › Cookie Setup",
        "Store only an opaque session id in the cookie; keep sensitive state server-side, set HttpOnly+Secure.",
    ),
    "CWE-522": (
        "Insufficiently Protected Credentials",
        "V13.3",
        "Configuration › Secret Management",
        "Load credentials from a mounted Secret / vault at runtime; never embed in source, image layers, or ConfigMaps.",
    ),
    "CWE-798": (
        "Use of Hard-coded Credentials",
        "V13.3",
        "Configuration › Secret Management",
        "Remove the literal; inject via Secret/env at deploy time and rotate the exposed value.",
    ),
    "CWE-256": (
        "Plaintext Storage of a Password",
        "V13.3",
        "Configuration › Secret Management",
        "Store only a salted hash (argon2id/bcrypt) or a reference to an external secret store.",
    ),
    "CWE-359": (
        "Exposure of Private Personal Information",
        "V14.2",
        "Data Protection › General Data Protection",
        "Mask or tokenise PII before logging/returning; enforce field-level access control.",
    ),
    "CWE-526": (
        "Cleartext Storage of Sensitive Information in an Environment Variable",
        "V13.3",
        "Configuration › Secret Management",
        "Don't `os.Setenv`/`export` secrets for child processes; pass them on stdin or via a scoped file descriptor and unset immediately after use.",
    ),
    "CWE-215": (
        "Insertion of Sensitive Information Into Debugging Code",
        "V13.4",
        "Configuration › Unintended Information Leakage",
        "Gate `Development:true`/debug loggers behind a build tag or env flag that defaults off in release builds.",
    ),
    "CWE-1059": (
        "Insufficient Technical Documentation",
        "V15.1",
        "Secure Coding & Architecture › Documentation",
        "Add SECURITY.md, dependency-update automation, and release provenance; wire OpenSSF Scorecard into CI.",
    ),
    "CWE-497": (
        "Exposure of System Data to an Unauthorized Control Sphere",
        "V13.4",
        "Configuration › Unintended Information Leakage",
        "Suppress build metadata, env dumps and internal paths from externally reachable endpoints.",
    ),
    "CWE-548": (
        "Exposure of Information Through Directory Listing",
        "V13.4",
        "Configuration › Unintended Information Leakage",
        "Disable autoindex/directory listing; serve only explicitly routed paths.",
    ),
    # ── auth / session / authz ─────────────────────────────────────────────
    "CWE-306": (
        "Missing Authentication for Critical Function",
        "V6.3",
        "Authentication › General Authentication Security",
        "Put the handler behind the auth middleware / require a verified identity before executing the action; deny by default.",
    ),
    "CWE-287": (
        "Improper Authentication",
        "V6.3",
        "Authentication › General Authentication Security",
        "Verify credential *and* bind result to the session; don't trust caller-supplied identity fields.",
    ),
    "CWE-862": (
        "Missing Authorization",
        "V8.3",
        "Authorization › Operation Level Authorization",
        "Add an explicit permission check that ties the *object* being acted on to the caller's identity/role.",
    ),
    "CWE-863": (
        "Incorrect Authorization",
        "V8.3",
        "Authorization › Operation Level Authorization",
        "Re-derive the resource owner server-side and compare to the authenticated principal; never trust client-sent owner/tenant IDs.",
    ),
    "CWE-639": (
        "Authorization Bypass Through User-Controlled Key (IDOR)",
        "V8.2",
        "Authorization › General Authorization Design",
        "Scope every lookup by the caller's tenant/owner in the query itself, not just the response filter.",
    ),
    "CWE-269": (
        "Improper Privilege Management",
        "V8.2",
        "Authorization › General Authorization Design",
        "Run with the minimum role/UID needed; drop capabilities immediately after the privileged step.",
    ),
    "CWE-250": (
        "Execution with Unnecessary Privileges",
        "V8.2",
        "Authorization › General Authorization Design",
        "Remove `privileged`/root; request only the specific Linux capability or K8s RBAC verb the code path needs.",
    ),
    "CWE-284": (
        "Improper Access Control",
        "V8.2",
        "Authorization › General Authorization Design",
        "Default-deny; enumerate the exact principals allowed and enforce at the entry point, not deep in the call stack.",
    ),
    "CWE-285": (
        "Improper Authorization",
        "V8.3",
        "Authorization › Operation Level Authorization",
        "Centralise the authz decision in one function and call it from every handler; add tests per role×operation.",
    ),
    "CWE-613": (
        "Insufficient Session Expiration",
        "V7.3",
        "Session Management › Session Timeout",
        "Set absolute + idle timeouts and invalidate the server-side session record on logout.",
    ),
    "CWE-384": (
        "Session Fixation",
        "V7.2",
        "Session Management › Fundamental Session Management Security",
        "Regenerate the session identifier on every privilege change (login, sudo, impersonate).",
    ),
    "CWE-346": (
        "Origin Validation Error",
        "V3.5",
        "Web Frontend › Browser Origin Separation",
        "Validate `Origin`/`Referer` against an allow-list before honouring state-changing requests or WebSocket upgrades.",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery (CSRF)",
        "V3.5",
        "Web Frontend › Browser Origin Separation",
        "Require a per-session anti-CSRF token (or SameSite=Strict cookies) on every state-changing route.",
    ),
    "CWE-290": (
        "Authentication Bypass by Spoofing",
        "V6.3",
        "Authentication › General Authentication Security",
        "Don't derive identity from spoofable inputs (Host header, X-Forwarded-*, client IP); authenticate the actual credential.",
    ),
    "CWE-303": (
        "Incorrect Implementation of Authentication Algorithm",
        "V6.3",
        "Authentication › General Authentication Security",
        "Use the framework's authenticator; delete the bespoke comparison / token-parsing code.",
    ),
    "CWE-288": (
        "Authentication Bypass Using an Alternate Path",
        "V6.3",
        "Authentication › General Authentication Security",
        "Register auth middleware on the router, not per-route; block direct access to internal handlers.",
    ),
    "CWE-1390": (
        "Weak Authentication",
        "V6.3",
        "Authentication › General Authentication Security",
        "Replace static/shared tokens with per-principal, time-bound credentials.",
    ),
    # ── TLS / transport ────────────────────────────────────────────────────
    "CWE-295": (
        "Improper Certificate Validation",
        "V12.3",
        "Secure Communication › Service-to-Service",
        "Delete `InsecureSkipVerify`/`verify=False`; load the CA bundle for the target and pin/hostname-verify.",
    ),
    "CWE-319": (
        "Cleartext Transmission of Sensitive Information",
        "V12.2",
        "Secure Communication › HTTPS with External Services",
        "Require TLS on the client (`https://`, `sslmode=require`) and refuse to fall back to plaintext.",
    ),
    "CWE-297": (
        "Improper Validation of Certificate with Host Mismatch",
        "V12.3",
        "Secure Communication › Service-to-Service",
        'Leave `ServerName`/SNI at its default so the library checks it against the cert SAN; don\'t override to `""`.',
    ),
    "CWE-326": (
        "Inadequate Encryption Strength",
        "V11.3",
        "Cryptography › Encryption Algorithms",
        "Raise key sizes to current minima (RSA-2048/AES-256/TLS1.2+) and disable legacy cipher suites.",
    ),
    "CWE-757": (
        "Selection of Less-Secure Algorithm During Negotiation",
        "V12.1",
        "Secure Communication › General TLS Guidance",
        "Set `MinVersion: TLS1.2` and an explicit cipher-suite allow-list; reject downgrade.",
    ),
    # ── crypto / randomness ────────────────────────────────────────────────
    "CWE-327": (
        "Use of a Broken or Risky Cryptographic Algorithm",
        "V11.3",
        "Cryptography › Encryption Algorithms",
        "Swap MD5/SHA1/DES/RC4 for SHA-256/AES-GCM/ChaCha20-Poly1305; use a vetted library primitive.",
    ),
    "CWE-328": (
        "Use of Weak Hash",
        "V11.4",
        "Cryptography › Hashing and Hash-based Functions",
        "Use SHA-256+ for integrity and argon2id/bcrypt for passwords.",
    ),
    "CWE-330": (
        "Use of Insufficiently Random Values",
        "V11.5",
        "Cryptography › Random Values",
        "Use `crypto/rand` (Go), `secrets` (Py), `crypto.randomBytes` (Node) — never `math/rand`/`random` for security decisions.",
    ),
    "CWE-338": (
        "Use of Cryptographically Weak PRNG",
        "V11.5",
        "Cryptography › Random Values",
        "Replace `math/rand`/`Math.random()` with the platform CSPRNG when the value guards access.",
    ),
    "CWE-321": (
        "Use of Hard-coded Cryptographic Key",
        "V11.2",
        "Cryptography › Secure Cryptography Implementation",
        "Load the key from a Secret/KMS at runtime; rotate the exposed key.",
    ),
    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "V9.1",
        "Self-contained Tokens › Source and Integrity",
        "Verify the signature *before* using any claim; pin the expected algorithm and key-id.",
    ),
    "CWE-916": (
        "Use of Password Hash With Insufficient Computational Effort",
        "V11.4",
        "Cryptography › Hashing and Hash-based Functions",
        "Hash passwords with argon2id/bcrypt/scrypt, not raw SHA-*.",
    ),
    "CWE-323": (
        "Reusing a Nonce/Key Pair in Encryption",
        "V11.3",
        "Cryptography › Encryption Algorithms",
        "Generate a fresh random nonce per message; never derive it from a counter you don't persist.",
    ),
    "CWE-331": (
        "Insufficient Entropy",
        "V11.5",
        "Cryptography › Random Values",
        "Seed from the OS CSPRNG; make identifiers ≥128 bits.",
    ),
    "CWE-1240": (
        "Use of a Cryptographic Primitive with a Risky Implementation",
        "V11.2",
        "Cryptography › Secure Cryptography Implementation",
        "Delete the hand-rolled crypto; call the stdlib/BoringSSL/`cryptography` primitive instead.",
    ),
    # ── injection / encoding ───────────────────────────────────────────────
    "CWE-78": (
        "OS Command Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Drop `shell=True`/`sh -c`; call the binary with an argv slice and validate each element against an allow-list.",
    ),
    "CWE-77": (
        "Command Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Build the command as a fixed argv array; never interpolate untrusted data into a single command string.",
    ),
    "CWE-88": (
        "Argument Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Prefix user-derived args with `--` and reject values that start with `-`; prefer library APIs over CLI shell-outs.",
    ),
    "CWE-89": (
        "SQL Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Use parameterised queries / the ORM's bind API; never concatenate identifiers or values into SQL.",
    ),
    "CWE-79": (
        "Cross-site Scripting (XSS)",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Context-encode at the sink (HTML/attr/JS/URL) or render via a framework that auto-escapes; ban `innerHTML`/`v-html` on untrusted data.",
    ),
    "CWE-74": (
        "Injection (generic)",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Separate code from data: use parameterised APIs and encode for the target interpreter.",
    ),
    "CWE-94": (
        "Code Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Remove `eval`/`exec`/`Function()` on external input; map input→action via a lookup table.",
    ),
    "CWE-90": (
        "LDAP Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Escape filter metacharacters via the LDAP library's escape function before building the filter string.",
    ),
    "CWE-91": (
        "XML Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Build XML with a DOM/builder API rather than string concat; disable DTD/external entities.",
    ),
    "CWE-943": (
        "Improper Neutralization in Data Query Logic",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Use the datastore driver's parameter binding; validate field names against a fixed allow-list.",
    ),
    "CWE-116": (
        "Improper Encoding or Escaping of Output",
        "V1.1",
        "Encoding & Sanitization › Architecture",
        "Encode at the last possible moment for the exact sink; centralise in one helper per sink.",
    ),
    "CWE-117": (
        "Improper Output Neutralization for Logs",
        "V16.4",
        "Security Logging › Log Protection",
        "Strip/escape CR-LF and control chars before logging user-controlled strings.",
    ),
    "CWE-1336": (
        "Server-Side Template Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Render user data as *context values* only; never let user input reach the template *source*.",
    ),
    "CWE-917": (
        "Expression Language Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "Disable EL evaluation on untrusted strings or use a sandboxed evaluator with an allow-listed function set.",
    ),
    # ── input validation / business logic ──────────────────────────────────
    "CWE-20": (
        "Improper Input Validation",
        "V2.2",
        "Validation & Business Logic › Input Validation",
        "Validate type, length, range and format at the trust boundary; reject rather than coerce.",
    ),
    "CWE-1287": (
        "Improper Validation of Specified Type of Input",
        "V2.2",
        "Validation & Business Logic › Input Validation",
        "Assert the exact schema/type (JSON-Schema, protobuf, struct tags) before use.",
    ),
    "CWE-185": (
        "Incorrect Regular Expression",
        "V2.2",
        "Validation & Business Logic › Input Validation",
        "Anchor the regex (`^…$`), escape user-derived fragments, and add a length precheck.",
    ),
    "CWE-1333": (
        "Inefficient Regular Expression (ReDoS)",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Rewrite catastrophic-backtracking patterns (nested `*`/`+`) or switch to RE2/linear-time engine; cap input length.",
    ),
    "CWE-345": (
        "Insufficient Verification of Data Authenticity",
        "V2.2",
        "Validation & Business Logic › Input Validation",
        "Verify a signature/MAC over the payload before acting on it; reject unsigned callbacks.",
    ),
    "CWE-602": (
        "Client-Side Enforcement of Server-Side Security",
        "V2.3",
        "Validation & Business Logic › Business Logic Security",
        "Repeat every security-relevant check on the server; treat client-side validation as UX only.",
    ),
    "CWE-807": (
        "Reliance on Untrusted Inputs in a Security Decision",
        "V2.3",
        "Validation & Business Logic › Business Logic Security",
        "Re-derive the decision input from a trusted source (DB, signed token), not from the request body.",
    ),
    "CWE-354": (
        "Improper Validation of Integrity Check Value",
        "V2.2",
        "Validation & Business Logic › Input Validation",
        "Compare digests with constant-time equality and fail closed on mismatch.",
    ),
    # ── SSRF / open-redirect / proxy ───────────────────────────────────────
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "V4.1",
        "API & Web Service › Generic Web Service Security",
        "Validate the destination against an allow-list *after* DNS resolution; block link-local/RFC1918/metadata ranges and disallow redirects.",
    ),
    "CWE-441": (
        "Unintended Proxy or Intermediary (Confused Deputy)",
        "V4.1",
        "API & Web Service › Generic Web Service Security",
        "Strip/ignore caller-supplied target URLs and forwarded-auth headers; re-authenticate downstream with the service's own identity.",
    ),
    "CWE-601": (
        "URL Redirection to Untrusted Site (Open Redirect)",
        "V4.1",
        "API & Web Service › Generic Web Service Security",
        "Only redirect to relative paths or an allow-listed host set; canonicalise before comparing.",
    ),
    "CWE-444": (
        "HTTP Request/Response Smuggling",
        "V4.2",
        "API & Web Service › HTTP Message Structure Validation",
        "Normalise/validate `Content-Length` vs `Transfer-Encoding` at the edge; reject ambiguous framing.",
    ),
    # ── files / paths / archives ───────────────────────────────────────────
    "CWE-22": (
        "Path Traversal",
        "V5.3",
        "File Handling › File Storage",
        "`filepath.Clean` + join under a fixed root, then verify the result is still under that root before open/write.",
    ),
    "CWE-23": (
        "Relative Path Traversal",
        "V5.3",
        "File Handling › File Storage",
        "Reject any path containing `..` after canonicalisation; resolve against a chroot-like base.",
    ),
    "CWE-73": (
        "External Control of File Name or Path",
        "V5.3",
        "File Handling › File Storage",
        "Map user-supplied names to server-generated IDs; never let the caller choose the on-disk path.",
    ),
    "CWE-59": (
        "Link Following (Symlink Attack)",
        "V5.3",
        "File Handling › File Storage",
        "Open with `O_NOFOLLOW`/`Lstat`-then-`Open` and verify the resolved inode is inside the expected directory.",
    ),
    "CWE-434": (
        "Unrestricted Upload of File with Dangerous Type",
        "V5.2",
        "File Handling › File Upload and Content",
        "Validate content-type by *sniffing*, restrict extensions, store outside the web root under a random name.",
    ),
    "CWE-552": (
        "Files or Directories Accessible to External Parties",
        "V5.4",
        "File Handling › File Download",
        "Serve downloads through a handler that authorises per-object, not by exposing the storage path.",
    ),
    "CWE-377": (
        "Insecure Temporary File",
        "V5.3",
        "File Handling › File Storage",
        "Create temp files with `os.CreateTemp`/`mkstemp` (0600) instead of predictable names in `/tmp`.",
    ),
    "CWE-378": (
        "Creation of Temporary File With Insecure Permissions",
        "V5.3",
        "File Handling › File Storage",
        "Pass mode 0600 when creating; on Go set `syscall.Umask` or `os.WriteFile(…, 0600)`.",
    ),
    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "V5.3",
        "File Handling › File Storage",
        "Write with 0600/0700 and chown to the service user; on K8s set `fsGroup`/`defaultMode`.",
    ),
    "CWE-276": (
        "Incorrect Default Permissions",
        "V5.3",
        "File Handling › File Storage",
        "Set an explicit restrictive mode at creation time; don't rely on the process umask.",
    ),
    "CWE-61": (
        "UNIX Symbolic Link Following",
        "V5.3",
        "File Handling › File Storage",
        "Use `openat2(RESOLVE_BENEATH)`/`SecureJoin`; never follow symlinks under a user-writable dir.",
    ),
    # ── deserialization / unsafe types ─────────────────────────────────────
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "V1.5",
        "Encoding & Sanitization › Safe Deserialization",
        "Use a safe loader (`yaml.safe_load`, `json.Unmarshal` into a fixed struct); allow-list types; never `pickle`/`ObjectInputStream` untrusted bytes.",
    ),
    "CWE-915": (
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)",
        "V1.5",
        "Encoding & Sanitization › Safe Deserialization",
        "Bind requests to a DTO with an explicit field allow-list; never `**kwargs`→model.",
    ),
    "CWE-1321": (
        "Prototype Pollution",
        "V1.5",
        "Encoding & Sanitization › Safe Deserialization",
        "Reject `__proto__`/`constructor`/`prototype` keys during merge; use `Object.create(null)` for maps.",
    ),
    "CWE-470": (
        "Unsafe Reflection",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Map input→class via a fixed table; never `Class.forName`/`getattr` on caller-supplied names.",
    ),
    "CWE-611": (
        "XML External Entity (XXE)",
        "V1.5",
        "Encoding & Sanitization › Safe Deserialization",
        "Disable DTDs and external entity resolution on the parser before loading untrusted XML.",
    ),
    # ── supply chain / dependency (source-side) ────────────────────────────
    "CWE-494": (
        "Download of Code Without Integrity Check",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Pin the download to a digest and verify the checksum/signature before executing or importing it.",
    ),
    "CWE-829": (
        "Inclusion of Functionality from Untrusted Control Sphere",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Vendor or pin the dependency by digest; review third-party code paths that run at import time.",
    ),
    "CWE-1104": (
        "Use of Unmaintained Third-Party Components",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Replace the dead dependency with a maintained fork or inline the minimal code you need under your own tests.",
    ),
    "CWE-1395": (
        "Dependency on Vulnerable Third-Party Component",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Bump to the fixed version and add a `go.mod`/`requirements` constraint so it can't regress.",
    ),
    "CWE-1357": (
        "Reliance on Insufficiently Trustworthy Component",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Pull only from a mirrored, signed registry; pin by digest, not tag.",
    ),
    "CWE-427": (
        "Uncontrolled Search Path Element",
        "V15.2",
        "Secure Coding & Architecture › Security Architecture & Dependencies",
        "Invoke binaries by absolute path and clear/fix `PATH`/`LD_LIBRARY_PATH` before `exec`.",
    ),
    # ── resource exhaustion / DoS ──────────────────────────────────────────
    "CWE-400": (
        "Uncontrolled Resource Consumption",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Bound request size, concurrency and duration; add `context` timeouts and per-caller rate limits.",
    ),
    "CWE-770": (
        "Allocation of Resources Without Limits or Throttling",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Cap slice/map growth by validated input length; use bounded channels/worker pools.",
    ),
    "CWE-674": (
        "Uncontrolled Recursion",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Add an explicit depth counter/limit or convert to an iterative walk with a bounded stack.",
    ),
    "CWE-405": (
        "Asymmetric Resource Consumption (Amplification)",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Cap fan-out per request and require auth before triggering expensive downstream work.",
    ),
    "CWE-789": (
        "Memory Allocation with Excessive Size Value",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Validate the caller-supplied length against a hard maximum before `make`/`malloc`.",
    ),
    "CWE-409": (
        "Decompression Bomb",
        "V5.2",
        "File Handling › File Upload and Content",
        "Wrap the decompressor in a `LimitedReader` and abort past a fixed expanded-size ceiling.",
    ),
    "CWE-834": (
        "Excessive Iteration",
        "V2.4",
        "Validation & Business Logic › Anti-automation",
        "Bound loop counts by validated input and add a watchdog timeout.",
    ),
    # ── memory / concurrency / defensive ───────────────────────────────────
    "CWE-190": (
        "Integer Overflow or Wraparound",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Use checked arithmetic / `math.SafeAdd` or validate operand ranges before the arithmetic drives an allocation or index.",
    ),
    "CWE-787": (
        "Out-of-bounds Write",
        "V1.4",
        "Encoding & Sanitization › Memory, String, and Unmanaged Code",
        "Bounds-check the index/length against the buffer capacity before every write; prefer safe slice ops.",
    ),
    "CWE-125": (
        "Out-of-bounds Read",
        "V1.4",
        "Encoding & Sanitization › Memory, String, and Unmanaged Code",
        "Validate offset+length ≤ len(buf) before slicing/reading.",
    ),
    "CWE-476": (
        "NULL Pointer Dereference",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Check for nil before dereference on every externally-influenced pointer; return an error instead of panicking.",
    ),
    "CWE-362": (
        "Race Condition",
        "V15.4",
        "Secure Coding & Architecture › Safe Concurrency",
        "Guard the shared state with a mutex or make the check-and-act a single atomic operation.",
    ),
    "CWE-367": (
        "TOCTOU Race Condition",
        "V15.4",
        "Secure Coding & Architecture › Safe Concurrency",
        "Operate on the file *descriptor* returned by the initial open rather than re-resolving the path.",
    ),
    "CWE-667": (
        "Improper Locking",
        "V15.4",
        "Secure Coding & Architecture › Safe Concurrency",
        "Acquire locks in a fixed global order; keep critical sections small; use `defer Unlock()`.",
    ),
    "CWE-416": (
        "Use After Free",
        "V1.4",
        "Encoding & Sanitization › Memory, String, and Unmanaged Code",
        "Null the pointer after free and gate all subsequent access on it; prefer ownership-tracking abstractions.",
    ),
    "CWE-415": (
        "Double Free",
        "V1.4",
        "Encoding & Sanitization › Memory, String, and Unmanaged Code",
        "Free in exactly one owner; set to NULL after free so a second free is a no-op or crash-early.",
    ),
    "CWE-252": (
        "Unchecked Return Value",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Handle the error return; on Go, don't `_ =` errors from security-relevant calls.",
    ),
    "CWE-390": (
        "Detection of Error Condition Without Action",
        "V16.5",
        "Security Logging › Error Handling",
        "Propagate or fail closed on the caught error; don't `catch (e) {}` around security checks.",
    ),
    "CWE-248": (
        "Uncaught Exception",
        "V16.5",
        "Security Logging › Error Handling",
        "Add a top-level recover/except that returns a controlled error instead of crashing the whole process.",
    ),
    "CWE-703": (
        "Improper Check or Handling of Exceptional Conditions",
        "V16.5",
        "Security Logging › Error Handling",
        "Distinguish error classes and fail closed on the security-relevant ones instead of swallowing all.",
    ),
    "CWE-754": (
        "Improper Check for Unusual or Exceptional Conditions",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Validate the precondition explicitly and return early with an error rather than proceeding on partial state.",
    ),
    "CWE-755": (
        "Improper Handling of Exceptional Conditions",
        "V16.5",
        "Security Logging › Error Handling",
        "Catch narrowly, log with context, and choose fail-closed vs retry deliberately per error class.",
    ),
    # ── config / defaults (source-side toggles) ────────────────────────────
    "CWE-1188": (
        "Initialization of a Resource with an Insecure Default",
        "V13.2",
        "Configuration › Backend Communication Configuration",
        "Flip the default to the secure value and require an explicit opt-out flag for the insecure mode.",
    ),
    "CWE-489": (
        "Active Debug Code",
        "V13.4",
        "Configuration › Unintended Information Leakage",
        "Strip debug/pprof/`--insecure` handlers from release builds or gate them behind localhost + auth.",
    ),
    "CWE-693": (
        "Protection Mechanism Failure",
        "V15.3",
        "Secure Coding & Architecture › Defensive Coding",
        "Remove the bypass flag/code path; make the guard unconditional in production builds.",
    ),
    "CWE-15": (
        "External Control of System or Configuration Setting",
        "V13.2",
        "Configuration › Backend Communication Configuration",
        "Allow-list which settings a caller may set and clamp values to a safe range.",
    ),
    "CWE-942": (
        "Permissive CORS Policy",
        "V3.5",
        "Web Frontend › Browser Origin Separation",
        "Reflect only allow-listed origins; never pair `*` with `Allow-Credentials: true`.",
    ),
    "CWE-16": (
        "Configuration",
        "V13.2",
        "Configuration › Backend Communication Configuration",
        "Set the secure value explicitly in code so it can't be overridden to an unsafe one at deploy time.",
    ),
    "CWE-923": (
        "Improper Restriction of Communication Channel to Intended Endpoints",
        "V13.2",
        "Configuration › Backend Communication Configuration",
        "Bind admin/debug listeners to localhost or a dedicated interface; require auth on anything bound to 0.0.0.0.",
    ),
    "CWE-668": (
        "Exposure of Resource to Wrong Sphere",
        "V13.2",
        "Configuration › Backend Communication Configuration",
        "Keep the resource on an internal listener/namespace; front it with an authenticating proxy if it must be reachable.",
    ),
    "CWE-749": (
        "Exposed Dangerous Method or Function",
        "V4.1",
        "API & Web Service › Generic Web Service Security",
        "Remove the endpoint or require an authenticated + authorised caller; never ship it enabled by default.",
    ),
    "CWE-472": (
        "External Control of Assumed-Immutable Web Parameter",
        "V2.3",
        "Validation & Business Logic › Business Logic Security",
        "Recompute price/role/owner server-side; ignore hidden/readonly fields from the client.",
    ),
    "CWE-565": (
        "Reliance on Cookies without Validation and Integrity Checking",
        "V7.2",
        "Session Management › Fundamental Session Management Security",
        "HMAC-sign the cookie or store only an opaque id and keep state server-side.",
    ),
    "CWE-778": (
        "Insufficient Logging",
        "V16.3",
        "Security Logging › Security Events",
        "Emit an audit-log record for every authn/authz decision and privileged action, with actor + object.",
    ),
    "CWE-1021": (
        "Improper Restriction of Rendered UI Layers (Clickjacking)",
        "V3.4",
        "Web Frontend › Browser Security Mechanism Headers",
        "Send `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`).",
    ),
    "CWE-1004": (
        "Sensitive Cookie Without HttpOnly",
        "V3.3",
        "Web Frontend › Cookie Setup",
        "Set `HttpOnly` (and `Secure`, `SameSite`) on every auth/session cookie.",
    ),
    "CWE-614": (
        "Sensitive Cookie Without Secure Attribute",
        "V3.3",
        "Web Frontend › Cookie Setup",
        "Set `Secure` on every cookie that carries auth/session state.",
    ),
    "CWE-644": (
        "Improper Neutralization of HTTP Headers",
        "V4.2",
        "API & Web Service › HTTP Message Structure Validation",
        "Strip CR/LF from any user-derived value before writing it into a response header.",
    ),
    "CWE-113": (
        "HTTP Response Splitting",
        "V4.2",
        "API & Web Service › HTTP Message Structure Validation",
        "Reject header values containing CR/LF; use the framework's header-set API, not raw writes.",
    ),
    "CWE-917-EL": (
        "(alias) EL Injection",
        "V1.2",
        "Encoding & Sanitization › Injection Prevention",
        "",
    ),
}

# any CWE not in the table above lands in one of these ASVS sections by first
# matching keyword in the CWE description (fetched from the finding title if
# needed) — but for reporting we group unmapped CWEs under this bucket.
UNMAPPED_ASVS = ("V15.3", "Secure Coding & Architecture › Defensive Coding")

# ASVS chapter id → name (for the dashboard chapter roll-up)
ASVS_CHAPTERS = {
    "V1": "Encoding and Sanitization",
    "V2": "Validation and Business Logic",
    "V3": "Web Frontend Security",
    "V4": "API and Web Service",
    "V5": "File Handling",
    "V6": "Authentication",
    "V7": "Session Management",
    "V8": "Authorization",
    "V9": "Self-contained Tokens",
    "V10": "OAuth and OIDC",
    "V11": "Cryptography",
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V14": "Data Protection",
    "V15": "Secure Coding and Architecture",
    "V16": "Security Logging and Error Handling",
    "V17": "WebRTC",
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

FUNC_PATTERNS = [
    # go
    re.compile(r"^\s*func\s+\((?:\w+\s+\*?\w+)\)\s+(\w+)\s*\(", re.M),
    re.compile(r"^\s*func\s+(\w+)\s*\(", re.M),
    # python / shell
    re.compile(r"^\s*def\s+(\w+)\s*\(", re.M),
    re.compile(r"^\s*(\w+)\s*\(\)\s*{", re.M),
    # js/ts
    re.compile(r"\bfunction\s+(\w+)\s*\(", re.M),
    re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?(?:const|let)\s+(\w+)\s*=\s*"
        r"(?:async\s*)?\(",
        re.M,
    ),
    re.compile(
        r"^\s*(?:public|private|protected)?\s*(?:async\s+)?(\w+)\s*\("
        r"[^)]*\)\s*{",
        re.M,
    ),
    # java / c# / kotlin
    re.compile(
        r"^\s*(?:public|private|protected|internal)\s+"
        r"(?:static\s+)?(?:[\w<>\[\],\s]+?\s+)?(\w+)\s*\(",
        re.M,
    ),
    # rust
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)", re.M),
]

DESC_FUNC = re.compile(r"\b([A-Z]\w+|\w+_\w+|\w{3,})\s*\(\)")


# ─────────────────────────────────────────────────────────────────────────────
def normalize_repo(url_or_path: str) -> str:
    """<forge-host>/owner/repo -> owner/repo for any forge; else leave as-is."""
    u = (url_or_path or "").strip().rstrip("/")
    m = re.match(r"^(?:https?://|git@|ssh://git@)?([a-z0-9.-]+\.[a-z]{2,})[:/](.+)$", u, re.I)
    for host in [m.group(1) + "/"] if m else []:
        if host in u.replace(":", "/", 1):
            tail = u.replace(":", "/", 1).split(host, 1)[1]
            parts = tail.split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1].removesuffix('.git')}"
    return u or "unknown"


def is_code_finding(f: dict) -> bool:
    """True if any location or evidence is source code (not config/manifest)."""
    saw_code = False
    for loc in f.get("locations") or []:
        p = loc.get("path", "")
        if CODE_EXT.search(p):
            saw_code = True
        elif CONFIG_EXT.search(p):
            pass
    for ev in f.get("evidence") or []:
        lang = (ev.get("language") or "").lower().strip()
        if lang in CODE_LANGS:
            saw_code = True
        elif lang in {
            "yaml",
            "yml",
            "json",
            "dockerfile",
            "toml",
            "ini",
            "hcl",
            "helm",
            "xml",
            "makefile",
            "text",
            "",
        }:
            pass
    return saw_code  # config-only ⇒ False


def extract_function(f: dict) -> str:
    """Best-effort function/method name from evidence or location description."""
    for ev in f.get("evidence") or []:
        code = ev.get("code") or ""
        for pat in FUNC_PATTERNS:
            m = pat.search(code)
            if m:
                name = m.group(1)
                if name and name not in {"if", "for", "while", "return", "switch", "func", "err"}:
                    return name
    for loc in f.get("locations") or []:
        desc = loc.get("description") or ""
        m = DESC_FUNC.search(desc)
        if m:
            return m.group(1)
    for loc in f.get("locations") or []:
        p = loc.get("path") or ""
        if CODE_EXT.search(p):
            base = os.path.basename(p)
            lines = loc.get("lines") or ""
            return f"{base}:{lines}" if lines else base
    return ""


def asvs_for(cwe: str) -> tuple[str, str, str]:
    """Return (section_id, section_name, chapter_name)."""
    meta = CWE_META.get(cwe)
    if meta:
        _name, sec_id, sec_name, _fix = meta
    else:
        sec_id, sec_name = UNMAPPED_ASVS
    chap_id = sec_id.rsplit(".", 1)[0]
    return sec_id, sec_name, ASVS_CHAPTERS.get(chap_id, chap_id)


# ─────────────────────────────────────────────────────────────────────────────
def collect(results_root: Path, tree: str = "findings"):
    """Walk reports under <results-root>/<tree>/, return per-CWE aggregation.

    `tree` selects which ownership tree to scan ("findings" = owned,
    "oss-findings" = upstream). Each call aggregates one tree in isolation:
    the dedup set, repo sets and stats never mix trees."""
    audit_reports = [str(x) for x in walk_reports(results_root / tree, "-security-audit.json")]
    # Prefer the cumulative report produced by the track-findings skill when
    # one sits next to the audit — its validation_status reflects human
    # triage and machine validation, so the false-positive drop below
    # actually bites.
    reports, dispositioned = [], 0
    for ap in sorted(audit_reports):
        cur = ap[: -len("security-audit.json")] + "findings-current.json"
        if cur.exists():
            reports.append(cur)
            dispositioned += 1
        else:
            reports.append(ap)
    patterns: dict[str, dict] = {}
    seen_occ: set[tuple] = set()  # (repo, cwe, path) — cross-branch de-dup
    stats = {
        "reports": 0,
        "reports_dispositioned": dispositioned,
        "findings_total": 0,
        "findings_code": 0,
        "findings_dropped_config": 0,
        "findings_dropped_fp": 0,
    }

    for fp in reports:
        try:
            d = json.load(open(fp))
        except Exception:
            continue
        stats["reports"] += 1
        repo = normalize_repo(d.get("metadata", {}).get("repository", ""))
        for f in d.get("findings") or []:
            stats["findings_total"] += 1
            if f.get("validation_status") == "false_positive":
                stats["findings_dropped_fp"] += 1
                continue
            if not is_code_finding(f):
                stats["findings_dropped_config"] += 1
                continue
            stats["findings_code"] += 1
            cwes = f.get("cwes") or []
            primary = cwes[0] if cwes else "CWE-0"
            loc0 = (f.get("locations") or [{}])[0]
            path = loc0.get("path", "")
            key = (repo, primary, path)
            if key in seen_occ:
                continue
            seen_occ.add(key)

            p = patterns.setdefault(
                primary,
                {
                    "cwe": primary,
                    "repos": set(),
                    "occurrences": 0,
                    "sev": collections.Counter(),
                    "co_cwes": collections.Counter(),
                    "examples": [],  # (sev_rank, repo, path, lines, function, title)
                    "titles": collections.Counter(),
                },
            )
            p["repos"].add(repo)
            p["occurrences"] += 1
            sev = (f.get("severity") or "informational").lower()
            p["sev"][sev] += 1
            for c in cwes[1:]:
                p["co_cwes"][c] += 1
            p["titles"][f.get("title", "")[:100]] += 1
            func = extract_function(f)
            lines = loc0.get("lines", "")
            ex = (SEV_ORDER.get(sev, 5), repo, path, lines, func, f.get("title", "")[:90])
            if len(p["examples"]) < 40:
                p["examples"].append(ex)
            elif ex[0] < max(e[0] for e in p["examples"]):
                # replace the lowest-severity example
                worst = max(range(len(p["examples"])), key=lambda i: p["examples"][i][0])
                p["examples"][worst] = ex

    # finalise
    out = []
    for cwe, p in patterns.items():
        name, fix = "", ""
        if cwe in CWE_META:
            name, _sid, _sn, fix = CWE_META[cwe]
        else:
            # derive a name from the most common finding title
            name = p["titles"].most_common(1)[0][0] if p["titles"] else cwe
            fix = (
                "See CWE description for remediation guidance; no curated fix in harness table yet."
            )
        sec_id, sec_name, chap_name = asvs_for(cwe)
        p["examples"].sort(key=lambda e: (e[0], e[1]))
        out.append(
            {
                "cwe": cwe,
                "name": name,
                "asvs_section": sec_id,
                "asvs_section_name": sec_name,
                "asvs_chapter": sec_id.rsplit(".", 1)[0],
                "asvs_chapter_name": chap_name,
                "fix": fix,
                "repo_count": len(p["repos"]),
                "occurrences": p["occurrences"],
                "severity": dict(p["sev"]),
                "highest_severity": min(
                    (s for s in p["sev"] if p["sev"][s] > 0),
                    key=lambda s: SEV_ORDER.get(s, 9),
                    default="informational",
                ),
                "repos": sorted(p["repos"]),
                "co_cwes": [c for c, _ in p["co_cwes"].most_common(5)],
                "examples": [
                    {
                        "repo": r,
                        "path": pa,
                        "lines": ln,
                        "function": fn,
                        "title": ti,
                        "severity": next(k for k, v in SEV_ORDER.items() if v == sr)
                        if sr in SEV_ORDER.values()
                        else "informational",
                    }
                    for sr, r, pa, ln, fn, ti in p["examples"][:12]
                ],
            }
        )
    out.sort(key=lambda p: (-p["repo_count"], -p["occurrences"]))
    return out, stats


# ─────────────────────────────────────────────────────────────────────────────
# renderers
# ─────────────────────────────────────────────────────────────────────────────
def sev_badge(sevs: dict) -> str:
    parts = []
    for k in ("critical", "high", "medium", "low", "informational"):
        if sevs.get(k):
            parts.append(f"{k[0].upper()}:{sevs[k]}")
    return " ".join(parts)


def _md_pattern_row(i, p) -> str:
    return (
        f"| {i} | [{p['cwe']}](https://cwe.mitre.org/data/definitions/"
        f"{p['cwe'].split('-')[1]}.html) | {p['name']} | "
        f"`{p['asvs_section']}` | {p['asvs_section_name']} | "
        f"**{p['repo_count']}** | {p['occurrences']} | "
        f"{sev_badge(p['severity'])} |"
    )


def _md_stats_row(label, stats) -> str:
    return (
        f"| {label} | {stats['reports']:,} | "
        f"{stats.get('reports_dispositioned', 0):,} | "
        f"{stats['findings_total']:,} | "
        f"**{stats['findings_code']:,}** | {stats['findings_dropped_config']:,} "
        f"| {stats['findings_dropped_fp']:,} |"
    )


def render_top25_md(patterns, stats, harness_version, up_patterns=None, up_stats=None) -> str:
    lines = [
        "# Insecure Coding Patterns — Portfolio Roll-up (Top 25)",
        "",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Harness:** `{harness_version}`  ",
        "**Scope:** `analysis-results/findings/` (owned ranking) + "
        "`analysis-results/oss-findings/` (tagged upstream cut) — "
        "source-code findings only (config/manifest gaps excluded)",
        "",
        "| Tree | Reports scanned | With dispositions | Total findings | "
        "Code findings kept | Config/manifest dropped | False-positives dropped |",
        "|---|---:|---:|---:|---:|---:|---:|",
        _md_stats_row("`findings/` (owned)", stats),
    ]
    if up_stats is not None:
        lines.append(_md_stats_row("`oss-findings/` (upstream)", up_stats))
    lines += [
        "",
        "> **Pattern = primary CWE.** Each finding's first CWE is the grouping "
        "key; the CWE is then mapped to its OWASP ASVS 5.0 section. "
        "**Repo count** is distinct repositories (branch reports de-duplicated). "
        "**Occurrences** is distinct `(repo, path)` tuples. "
        "All ranked tables below cover the **owned tree only**; the upstream "
        "tree is reported separately in the *Upstream cut* section and is "
        "never folded into the owned ranking.",
        "",
        "## Top 25 insecure coding patterns by repository count",
        "",
        "| # | CWE | Pattern | ASVS 5.0 § | ASVS category | Repos | Occurrences | Severity mix |",
        "|--:|---|---|---|---|--:|--:|---|",
    ]
    for i, p in enumerate(patterns[:25], 1):
        lines.append(_md_pattern_row(i, p))
    # ASVS chapter roll-up
    chap = collections.Counter()
    chap_repos = collections.defaultdict(set)
    for p in patterns:
        chap[p["asvs_chapter"]] += p["occurrences"]
        chap_repos[p["asvs_chapter"]].update(p["repos"])
    lines += [
        "",
        "## Distribution by ASVS 5.0 chapter",
        "",
        "| Chapter | Area | Distinct repos | Code-finding occurrences |",
        "|---|---|--:|--:|",
    ]
    for cid, occ in sorted(chap.items(), key=lambda kv: -len(chap_repos[kv[0]])):
        lines.append(
            f"| `{cid}` | {ASVS_CHAPTERS.get(cid, cid)} | {len(chap_repos[cid])} | {occ} |"
        )
    # upstream cut — tagged, adjacent, never merged into the owned ranking
    if up_stats is not None:
        lines += [
            "",
            "## Upstream cut (oss-findings/)",
            "",
            f"Upstream community code Hybrid Platforms depends on — "
            f"{up_stats['reports']:,} reports "
            f"({up_stats.get('reports_dispositioned', 0):,} with dispositions), "
            f"{up_stats['findings_code']:,} code findings kept. "
            "Same code-only / false-positive-drop / `(repo, cwe, path)` "
            "de-duplication rules, applied **within the upstream tree only**. "
            "Upstream occurrences are **never folded into the owned ranking, "
            "repo counts, or examples** above.",
            "",
        ]
        if up_patterns:
            lines += [
                "| # | CWE | Pattern | ASVS 5.0 § | ASVS category | Repos | "
                "Occurrences | Severity mix |",
                "|--:|---|---|---|---|--:|--:|---|",
            ]
            for i, p in enumerate(up_patterns[:10], 1):
                lines.append(_md_pattern_row(i, p))
        else:
            lines.append("*No upstream code findings in scope.*")
    lines += [
        "",
        "## Method",
        "",
        "1. Every `*-security-audit.json` under `findings/` (owned) and "
        "`oss-findings/` (upstream) is parsed, tagged with its tree; when a "
        "sibling `*-findings-current.json` (track-findings cumulative report) "
        "exists it is used instead, so human triage and machine validation "
        "dispositions are honoured. The two trees are aggregated separately: "
        "owned drives the ranked tables, upstream feeds only the *Upstream "
        "cut* section.",
        "1a. Findings whose `validation_status` is `false_positive` are "
        "dropped before pattern counting.",
        "2. A finding is kept only if ≥1 location path or evidence block is a "
        "source-code language (Go, Python, TS/JS, Java, C/C++, Rust, shell, …). "
        "Findings whose only artifacts are YAML/JSON/Dockerfile/Helm/TOML "
        "are dropped as config/manifest gaps.",
        "3. Occurrences are de-duplicated by `(repo, primary-CWE, file-path)` "
        "so that per-branch report copies count once.",
        "4. CWE → ASVS 5.0 section via the curated table in "
        "`harnessing/insecure-patterns/scripts/build_insecure_patterns.py::CWE_META` "
        "(ASVS 5.0 dropped its own CWE column, so this mapping is maintained "
        "in-harness).",
        "",
        "See `insecure-patterns-detailed.md` for per-pattern example "
        "functions and root-cause fixes, and "
        "`insecure-patterns-dashboard.html` for the interactive view.",
        "",
    ]
    return "\n".join(lines)


def render_detailed_md(patterns, stats, harness_version) -> str:
    lines = [
        "# Insecure Coding Patterns — Detailed (Top 50)",
        "",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"**Harness:** `{harness_version}` · "
        f"**Code findings:** {stats['findings_code']:,} across "
        f"{stats['reports']:,} reports",
        "",
        "Each pattern below is one CWE, mapped to its OWASP ASVS 5.0 section, "
        "with representative `repo · file · function` examples drawn from the "
        "audit corpus and a one/two-line root-cause fix. Examples are ordered "
        "highest-severity-first.",
        "",
        "---",
        "",
    ]
    for i, p in enumerate(patterns[:50], 1):
        sev = p["highest_severity"]
        lines += [
            f"## {i}. {p['cwe']} — {p['name']}",
            "",
            f"**ASVS 5.0:** `{p['asvs_section']}` {p['asvs_section_name']} "
            f"· **Chapter:** {p['asvs_chapter']} {p['asvs_chapter_name']}  ",
            f"**Repos affected:** {p['repo_count']} · "
            f"**Occurrences:** {p['occurrences']} · "
            f"**Highest severity:** {sev} · "
            f"**Mix:** {sev_badge(p['severity'])}"
            + (f" · **Often co-tagged:** {', '.join(p['co_cwes'])}" if p["co_cwes"] else ""),
            "",
            f"**Root-cause fix:** {p['fix']}",
            "",
            "**Example functions/locations:**",
            "",
            "| Repo | File:Lines | Function | Finding title |",
            "|---|---|---|---|",
        ]
        for ex in p["examples"][:6]:
            fn = f"`{ex['function']}`" if ex["function"] else ""
            path = ex["path"]
            if ex["lines"]:
                path = f"{path}:{ex['lines']}"
            title = ex["title"].replace("|", "\\|")
            lines.append(f"| `{ex['repo']}` | `{path}` | {fn} | {title} |")
        if p["repo_count"] > 6:
            more = ", ".join(
                f"`{r}`" for r in p["repos"][:12] if r not in {e["repo"] for e in p["examples"][:6]}
            )
            if more:
                lines.append("")
                lines.append(
                    f"*Also in:* {more}"
                    + (f" … (+{p['repo_count'] - 12} more)" if p["repo_count"] > 12 else "")
                )
        lines += ["", "---", ""]
    return "\n".join(lines)


def render_dashboard_html(patterns, stats, harness_version, up_patterns=None, up_stats=None) -> str:
    top = patterns[:50]
    chap = collections.Counter()
    chap_repos = collections.defaultdict(set)
    for p in patterns:
        chap[p["asvs_chapter"]] += p["occurrences"]
        chap_repos[p["asvs_chapter"]].update(p["repos"])
    chap_rows = sorted(
        ((cid, ASVS_CHAPTERS.get(cid, cid), len(chap_repos[cid]), chap[cid]) for cid in chap),
        key=lambda r: -r[2],
    )
    max_repo = max((p["repo_count"] for p in top), default=1)

    # colours per ASVS chapter
    palette = {
        "V1": "#e85d75",
        "V2": "#f4a261",
        "V3": "#e9c46a",
        "V4": "#8ab17d",
        "V5": "#2a9d8f",
        "V6": "#4cc9f0",
        "V7": "#4895ef",
        "V8": "#4361ee",
        "V9": "#7209b7",
        "V10": "#b5179e",
        "V11": "#f72585",
        "V12": "#ff6d00",
        "V13": "#8d99ae",
        "V14": "#06d6a0",
        "V15": "#577590",
        "V16": "#bc6c25",
        "V17": "#6c757d",
    }

    def esc(s):
        return html.escape(str(s))

    rows_html = []
    for i, p in enumerate(top, 1):
        pct = round(100 * p["repo_count"] / max_repo)
        sev = "".join(
            f'<span class="sev sev-{k}">{v}</span>'
            for k in ("critical", "high", "medium", "low", "informational")
            if (v := p["severity"].get(k))
        )
        col = palette.get(p["asvs_chapter"], "#8b949e")
        ex_html = "".join(
            f'<div class="ex"><code>{esc(e["repo"])}</code> — '
            f"<code>{esc(e['path'])}"
            f"{':' + esc(e['lines']) if e['lines'] else ''}</code>"
            f"{' · <b>' + esc(e['function']) + '()</b>' if e['function'] else ''}"
            f'<div class="ex-title">{esc(e["title"])}</div></div>'
            for e in p["examples"][:5]
        )
        rows_html.append(f"""
<tr data-chapter="{p["asvs_chapter"]}" data-cwe="{p["cwe"]}">
  <td class="num">{i}</td>
  <td><a href="https://cwe.mitre.org/data/definitions/{p["cwe"].split("-")[1]}.html"
         class="cwe">{p["cwe"]}</a></td>
  <td class="pat"><b>{esc(p["name"])}</b>
      <div class="fix">{esc(p["fix"])}</div>
      <details><summary>examples</summary>{ex_html}</details></td>
  <td><span class="chip" style="background:{col}33;color:{col}">
      {p["asvs_section"]}</span>
      <div class="sec">{esc(p["asvs_section_name"])}</div></td>
  <td class="num repo-col"><b>{p["repo_count"]}</b>
      <div class="bar"><span style="width:{pct}%;background:{col}"></span></div></td>
  <td class="num">{p["occurrences"]}</td>
  <td class="sev-cell">{sev}</td>
</tr>""")

    chap_html = "".join(
        f'<div class="crow"><span class="chip" '
        f'style="background:{palette.get(cid, "#8b949e")}33;'
        f'color:{palette.get(cid, "#8b949e")}">{cid}</span> '
        f'<span class="cname">{esc(cname)}</span>'
        f'<span class="cnum">{repos} repos · {occ} occ</span>'
        f'<div class="cbar"><span style="width:'
        f"{round(100 * repos / max(r for _, _, r, _ in chap_rows))}%;"
        f'background:{palette.get(cid, "#8b949e")}"></span></div></div>'
        for cid, cname, repos, occ in chap_rows
    )

    chap_options = "".join(
        f'<option value="{cid}">{cid} — {esc(cname)}</option>' for cid, cname, _, _ in chap_rows
    )

    # upstream cut panel — tagged, adjacent, never merged into owned ranking
    upstream_panel = ""
    if up_stats is not None:
        if up_patterns:
            up_rows = "".join(
                f'<tr><td class="num">{i}</td>'
                f'<td><a href="https://cwe.mitre.org/data/definitions/'
                f'{p["cwe"].split("-")[1]}.html" class="cwe">{p["cwe"]}</a></td>'
                f'<td class="pat"><b>{esc(p["name"])}</b></td>'
                f'<td><span class="chip" style="background:'
                f"{palette.get(p['asvs_chapter'], '#8b949e')}33;color:"
                f'{palette.get(p["asvs_chapter"], "#8b949e")}">'
                f"{p['asvs_section']}</span>"
                f'<div class="sec">{esc(p["asvs_section_name"])}</div></td>'
                f'<td class="num"><b>{p["repo_count"]}</b></td>'
                f'<td class="num">{p["occurrences"]}</td>'
                f'<td class="sev-cell">'
                + "".join(
                    f'<span class="sev sev-{k}">{v}</span>'
                    for k in ("critical", "high", "medium", "low", "informational")
                    if (v := p["severity"].get(k))
                )
                + "</td></tr>"
                for i, p in enumerate(up_patterns[:10], 1)
            )
            up_table = (
                f"<table><thead><tr><th>#</th><th>CWE</th>"
                f"<th>Pattern</th><th>ASVS 5.0</th>"
                f'<th class="num">Repos</th><th class="num">Occ</th>'
                f"<th>Severity</th></tr></thead>"
                f"<tbody>{up_rows}</tbody></table>"
            )
        else:
            up_table = (
                '<div style="color:var(--muted);font-size:13px">'
                "No upstream code findings in scope.</div>"
            )
        upstream_panel = f"""
<div class="panel">
<h2>Upstream cut (oss-findings/) — top 10 by repo count</h2>
<div style="color:var(--muted);font-size:12px;margin-bottom:10px">
Upstream community code Hybrid Platforms depends on ·
{up_stats["reports"]:,} reports scanned ·
{up_stats["findings_code"]:,} code findings kept ·
same code-only / FP-drop / (repo,&nbsp;cwe,&nbsp;path) dedup rules applied
within the upstream tree only.
<b>Upstream is never folded into the owned ranking above.</b></div>
{up_table}
</div>
"""

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Insecure Coding Patterns — ASVS 5.0 roll-up</title>
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--border:#30363d;
--panel:#161b22;--accent:#58a6ff}}
*{{box-sizing:border-box}}
body{{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}}
h1{{margin:0 0 4px;font-size:22px}}
.sub{{color:var(--muted);margin-bottom:20px;font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
gap:12px;margin-bottom:20px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:14px}}
.card .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.5px}}
.card .val{{font-size:24px;font-weight:600;margin-top:4px}}
.panel{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:16px;margin-bottom:20px}}
h2{{margin:0 0 12px;font-size:15px;color:var(--muted);text-transform:uppercase;
letter-spacing:.5px}}
.crow{{display:grid;grid-template-columns:60px 1fr 180px;gap:12px;
align-items:center;padding:6px 0}}
.cname{{font-size:13px}}
.cnum{{font-size:12px;color:var(--muted);text-align:right}}
.cbar{{grid-column:1/-1;height:5px;background:var(--border);border-radius:3px;
overflow:hidden}}
.cbar span{{display:block;height:100%}}
.controls{{display:flex;gap:12px;margin-bottom:12px;align-items:center}}
.controls input,.controls select{{background:#0d1117;color:var(--fg);
border:1px solid var(--border);border-radius:6px;padding:6px 10px;font:inherit}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:10px 12px;color:var(--muted);font-size:11px;
text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);
position:sticky;top:0;background:var(--panel)}}
td{{padding:12px;border-bottom:1px solid var(--border);vertical-align:top}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.pat b{{font-size:14px}}
.fix{{color:var(--muted);font-size:12px;margin-top:4px;max-width:560px}}
.sec{{color:var(--muted);font-size:11px;margin-top:2px}}
.chip{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;
font-weight:600;font-family:ui-monospace,monospace}}
.cwe{{color:var(--accent);text-decoration:none;
font-family:ui-monospace,monospace}}
.bar{{height:5px;background:var(--border);border-radius:3px;overflow:hidden;
margin-top:6px}}
.bar span{{display:block;height:100%}}
.repo-col{{min-width:110px}}
.sev{{display:inline-block;min-width:24px;text-align:center;padding:1px 5px;
border-radius:3px;font-size:10px;font-weight:600;margin-right:2px}}
.sev-critical{{background:#da3633aa;color:#fff}}
.sev-high{{background:#e8590caa;color:#fff}}
.sev-medium{{background:#bf8700aa;color:#fff}}
.sev-low{{background:#1f6febaa;color:#fff}}
.sev-informational{{background:#6e7681aa;color:#fff}}
details summary{{cursor:pointer;color:var(--accent);font-size:12px;
margin-top:6px}}
.ex{{font-size:11px;padding:6px 0;border-top:1px solid var(--border)}}
.ex code{{color:#79c0ff}}
.ex-title{{color:var(--muted);margin-top:2px}}
.table-wrap{{max-height:70vh;overflow-y:auto;border:1px solid var(--border);
border-radius:6px}}
tr.hidden{{display:none}}
.count{{color:var(--muted);font-size:12px}}
</style></head><body>
<h1>Insecure Coding Patterns — OWASP ASVS 5.0 roll-up</h1>
<div class="sub">Source-code findings only (config/manifest gaps excluded) ·
owned tree (findings/) drives all ranked tables; the upstream tree
(oss-findings/) appears only in the tagged upstream-cut panel below ·
generated {esc(datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))} ·
harness <code>{esc(harness_version)}</code></div>

<div class="cards">
  <div class="card"><div class="lbl">Reports scanned</div>
    <div class="val">{stats["reports"]:,}</div></div>
  <div class="card"><div class="lbl">Code findings</div>
    <div class="val">{stats["findings_code"]:,}</div></div>
  <div class="card"><div class="lbl">Config/manifest dropped</div>
    <div class="val">{stats["findings_dropped_config"]:,}</div></div>
  <div class="card"><div class="lbl">Distinct patterns (CWEs)</div>
    <div class="val">{len(patterns)}</div></div>
  <div class="card"><div class="lbl">Repos with ≥1 code finding</div>
    <div class="val">{len({r for p in patterns for r in p["repos"]}):,}</div></div>
</div>

<div class="panel">
<h2>ASVS 5.0 chapter distribution</h2>
{chap_html}
</div>

<div class="panel">
<h2>Top 50 patterns</h2>
<div class="controls">
  <input id="filter" placeholder="filter CWE / pattern / fix…">
  <select id="chap-filter"><option value="">All ASVS chapters</option>
  {chap_options}</select>
  <span class="count" id="row-count"></span>
</div>
<div class="table-wrap">
<table id="tbl">
<thead><tr>
  <th>#</th><th>CWE</th><th>Pattern &amp; fix</th><th>ASVS 5.0</th>
  <th class="num">Repos</th><th class="num">Occ</th><th>Severity</th>
</tr></thead>
<tbody>
{"".join(rows_html)}
</tbody></table>
</div></div>
{upstream_panel}
<script>
(function(){{
const rows=[...document.querySelectorAll('#tbl tbody tr')];
const f=document.getElementById('filter');
const c=document.getElementById('chap-filter');
const rc=document.getElementById('row-count');
function apply(){{
  const q=f.value.toLowerCase();const ch=c.value;let n=0;
  for(const r of rows){{
    const show=(!ch||r.dataset.chapter===ch)&&
               (!q||r.textContent.toLowerCase().includes(q));
    r.classList.toggle('hidden',!show);if(show)n++;
  }}
  rc.textContent=n+' / '+rows.length+' shown';
}}
f.oninput=apply;c.onchange=apply;apply();
}})();
</script>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
def harness_version(harness_root: Path) -> str:
    try:
        return engine_harness_version()
    except Exception:
        v = "0.0.0"
        with contextlib.suppress(Exception):
            v = (harness_root / "VERSION").read_text().strip()
        return v


# --- shared metrics ledger (best-effort; dashboards never fail on it) -------


def _population_lines(stats, up_stats=None, engine=None):
    """Standard population block (traust.cli.groups.corpus); None when unavailable.

    Reporting only — describes exactly what collect() already scanned; the
    glob, filters and dedup are unchanged. Counts are split owned
    (findings/) vs upstream (oss-findings/); the upstream tree feeds only
    the tagged upstream cut, never the owned ranking."""
    try:
        from traust_engine.corpus import resolver as corpus

        cfg = engine.corpus.config() if engine is not None else corpus.load_config()

        def _split(key, default=None):
            owned = stats.get(key, default)
            up = (up_stats or {}).get(key, default)
            if up_stats is None:
                return f"{owned:,}"
            return f"{owned:,} owned + {up:,} upstream"

        return corpus.population_block_lines(
            tool="insecure-patterns",
            roots=corpus.roots_description(
                cfg, ["findings", "oss-findings"] if up_stats is not None else ["findings"]
            ),
            unit="source-code findings bucketed by primary CWE; "
            "occurrences deduped by (repo, cwe, path) within each tree",
            filters="config/manifest-only findings dropped; false positives "
            "dropped (disposition-aware); hardening KEPT; trees "
            "aggregated separately — upstream never folded into the "
            "owned ranking",
            denominator="recursive glob of "
            "{findings,oss-findings}/**/*-security-audit.json "
            "(findings-current preferred when present)",
            counts={
                "Reports scanned": _split("reports"),
                "With dispositions": _split("reports_dispositioned", 0),
                "Total findings": _split("findings_total"),
                "Code findings kept": _split("findings_code"),
                "Config/manifest dropped": _split("findings_dropped_config"),
                "False positives dropped": _split("findings_dropped_fp"),
            },
        )
    except Exception as e:  # pragma: no cover — block is best-effort
        print(f"population block unavailable: {e}", file=sys.stderr)
        return None


def _inject_trend(path, text):
    """Insert the trend line into an already-rendered output (md or html)."""
    try:
        import re as _re
        from pathlib import Path as _P

        p = _P(path)
        s = p.read_text(encoding="utf-8")
        if p.suffix == ".md":
            head, _, rest = s.partition("\n")
            s = head + f"\n\n\U0001f4c8 *{text}*\n" + rest
        else:
            s = _re.sub(
                r"(<body[^>]*>)",
                lambda m: (
                    m.group(1) + "<div style='max-width:1280px;margin:10px auto 0;"
                    "padding:0 28px;font-size:13px;color:#6a6e73'>"
                    "\U0001f4c8 " + text + "</div>"
                ),
                s,
                count=1,
            )
        p.write_text(s, encoding="utf-8")
    except OSError:
        pass


def _dashboards_home(engine):
    """Dashboards live with the metrics, separate from findings data."""
    from traust_engine import locations

    try:
        pt = locations.require(
            locations.progress_tracker_dir(engine.ctx.locations),
            "progress_tracker",
        )
        out = pt / "metrics" / "dashboards"
        out.mkdir(parents=True, exist_ok=True)
        return out
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="analysis-results directory (contains findings/)",
    )
    ap.add_argument(
        "--out-dir",
        default=None,
        help="output directory (default: <results-root>/insecure-patterns/)",
    )
    ap.add_argument("--summary", action="store_true", help="print top-25 table to stderr")
    args = ap.parse_args()

    engine = load_engine(args.config_home)
    harness_root = HARNESS_ROOT
    root = resolve_results_root(args)
    if not (root / "findings").is_dir():
        sys.exit(f"error: {root}/findings/ not found — pass --results-root")

    out_dir = (
        Path(args.out_dir).expanduser().resolve()
        if args.out_dir
        else ((_dashboards_home(engine) or root) / "insecure-patterns")
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"results root: {root}", file=sys.stderr)
    print("scanning reports …", file=sys.stderr)
    patterns, stats = collect(root, "findings")
    print(
        f"  owned (findings/): {stats['reports']:,} reports "
        f"({stats.get('reports_dispositioned', 0):,} with dispositions), "
        f"{stats['findings_total']:,} findings → "
        f"{stats['findings_code']:,} code findings kept "
        f"({stats['findings_dropped_config']:,} config/manifest dropped, "
        f"{stats['findings_dropped_fp']:,} FP dropped)",
        file=sys.stderr,
    )

    # upstream cut — oss-findings/ (upstream community code HP depends on).
    # Aggregated with the same rules but kept separate: never folded into
    # the owned ranking, repo counts, or examples.
    up_patterns, up_stats = (
        collect(root, "oss-findings") if (root / "oss-findings").is_dir() else (None, None)
    )
    if up_stats is not None:
        print(
            f"  upstream (oss-findings/): {up_stats['reports']:,} reports "
            f"({up_stats.get('reports_dispositioned', 0):,} with "
            f"dispositions), {up_stats['findings_total']:,} findings → "
            f"{up_stats['findings_code']:,} code findings kept "
            f"({up_stats['findings_dropped_config']:,} config/manifest "
            f"dropped, {up_stats['findings_dropped_fp']:,} FP dropped)",
            file=sys.stderr,
        )
    else:
        print(
            "  upstream (oss-findings/): tree not present — upstream cut skipped", file=sys.stderr
        )

    hv = harness_version(harness_root)

    payload = {
        "metadata": {
            "generated": datetime.now(UTC).isoformat(),
            "harness_version": hv,
            "results_root": str(root),
            "asvs_version": "5.0.0",
            "asvs_source": "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/"
            "docs_en/OWASP_Application_Security_Verification_"
            "Standard_5.0.0_en.flat.json",
        },
        # owned tree (findings/) — unchanged keys, owned-only numbers
        "stats": stats,
        "patterns": patterns,
    }
    if up_stats is not None:
        # additive upstream cut — nothing existing renamed
        payload["upstream"] = {
            "tree": "oss-findings",
            "ownership": "upstream",
            "note": "Upstream community code HP depends on; same "
            "code-only/FP-drop/(repo,cwe,path)-dedup rules applied "
            "within this tree only. Never folded into the owned "
            "stats/patterns above.",
            "stats": up_stats,
            "patterns": up_patterns,
        }
    (out_dir / "insecure-patterns.json").write_text(json.dumps(payload, indent=2))
    pop_lines = _population_lines(stats, up_stats, engine)
    pop_md = ("\n---\n\n" + "\n".join(pop_lines) + "\n") if pop_lines else ""
    pop_panel = ""
    if pop_lines:
        pop_items = "".join(
            "<li>"
            + re.sub(
                r"\*\*(.+?):\*\*",
                r"<b>\1:</b>",
                html.escape(ln[2:] if ln.startswith("- ") else ln),
                count=1,
            )
            + "</li>"
            for ln in pop_lines
            if ln and ln != "## Population"
        )
        pop_panel = (
            f'<div class="panel"><h2>Population</h2>'
            f'<ul style="font-size:12px;margin:0;padding-left:18px">'
            f"{pop_items}</ul></div>\n"
        )

    (out_dir / "insecure-patterns-top25.md").write_text(
        render_top25_md(patterns, stats, hv, up_patterns, up_stats).rstrip("\n") + "\n" + pop_md
    )
    (out_dir / "insecure-patterns-detailed.md").write_text(
        render_detailed_md(patterns, stats, hv).rstrip("\n") + "\n" + pop_md
    )
    (out_dir / "insecure-patterns-dashboard.html").write_text(
        render_dashboard_html(patterns, stats, hv, up_patterns, up_stats).replace(
            "</body></html>", pop_panel + "</body></html>"
        )
    )

    try:
        headline = {
            "code_findings": stats.get("findings_code"),
            "distinct_cwes": len(patterns),
            "repos_audited": stats.get("reports"),
        }
        prev = engine.metrics.previous("insecure-patterns")
        from traust_engine.metrics import history as metrics_history

        tline = metrics_history.trend_line(headline, prev, ["code_findings", "distinct_cwes"])
        if tline:
            _inject_trend(out_dir / "insecure-patterns-top25.md", tline)
            _inject_trend(out_dir / "insecure-patterns-dashboard.html", tline)
        if engine.metrics.append_if_changed("insecure-patterns", headline):
            print("metrics snapshot appended (insecure-patterns)", file=sys.stderr)
    except Exception:
        pass

    for f in (
        "insecure-patterns.json",
        "insecure-patterns-top25.md",
        "insecure-patterns-detailed.md",
        "insecure-patterns-dashboard.html",
    ):
        p = out_dir / f
        print(f"wrote {p} ({p.stat().st_size:,} bytes)", file=sys.stderr)

    if args.summary:
        print("\nTop 25:", file=sys.stderr)
        print(f"{'#':>3} {'CWE':10} {'Repos':>6} {'Occ':>6}  {'ASVS':6} Pattern", file=sys.stderr)
        for i, p in enumerate(patterns[:25], 1):
            print(
                f"{i:3d} {p['cwe']:10} {p['repo_count']:6d} "
                f"{p['occurrences']:6d}  {p['asvs_section']:6} "
                f"{p['name'][:50]}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
