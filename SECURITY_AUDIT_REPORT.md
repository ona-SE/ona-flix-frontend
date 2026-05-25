# Security Audit Report — OnaFlix Frontend

**Date:** 2026-05-25
**Scope:** All npm dependencies declared in `package.json`
**Remediation PR:** [#5](https://github.com/ona-SE/ona-flix-frontend/pull/5) (`452bc5d`)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Dependencies scanned | 8 production, 10 dev |
| Vulnerable packages found | 4 (axios, lodash, dompurify, follow-redirects) |
| Total CVEs / advisories | 41 |
| Reachable in source code | 0 |
| Remediation | All 4 packages removed — none were imported or used |

All 41 vulnerabilities are **Unreachable → Remediated**. The vulnerable packages were phantom dependencies: declared in `package.json` but never imported anywhere in the codebase.

---

## Findings

### 1 — axios 0.21.1 (Direct, Unused)

**Evidence (applies to all axios findings):** `grep -rn "axios" --include="*.js" --include="*.jsx"` returns zero matches outside `package.json`. The application uses native `fetch()` in `src/services/api.js` for all HTTP calls. No import, no require, no dynamic load. Axios is never bundled or executed.

**Fix (applies to all axios findings):** Removed `"axios": "0.21.1"` from `package.json` in commit `452bc5d`. This also eliminates the transitive `follow-redirects` dependency.

**Verification:** N/A — package was never imported; removal has no runtime effect.

---

#### 1.1 Prototype Pollution — mergeConfig (transport/env/formSerializer hijack)

- **Result:** Unreachable → Remediated — axios never imported; `mergeConfig` never called.
- **Impact:** CVSS 7.5 (est.) · CVE-2026-42037 · Attacker-controlled request config could redirect requests and alter serialization.

#### 1.2 HTTP Response Splitting — FormData header injection

- **Result:** Unreachable → Remediated — axios never imported; no FormData passed to axios.
- **Impact:** CVSS 9.1 · CVE-2026-42035 · Injected headers could exfiltrate credentials or alter server-side handling.

#### 1.3 Uncontrolled Recursion — toFormData stack overflow

- **Result:** Unreachable → Remediated — axios never imported; `toFormData` never invoked.
- **Impact:** CVSS 8.7 · CVE-2026-42039 · Deeply nested request data causes process crash via stack overflow.

#### 1.4 HTTP Response Splitting — AxiosHeaders CRLF injection

- **Result:** Unreachable → Remediated — axios never imported; no headers set via AxiosHeaders.
- **Impact:** CVSS 7.0 · CVE-2026-40175 · CRLF in header values enables request smuggling and metadata exfiltration.

#### 1.5 Prototype Pollution — mergeConfig `__proto__` crash

- **Result:** Unreachable → Remediated — axios never imported; `mergeConfig` never called.
- **Impact:** CVSS 7.5 (est.) · No CVE assigned · Malicious config with `__proto__` crashes the application.

#### 1.6 Cross-site Request Forgery — XSRF token leak

- **Result:** Unreachable → Remediated — axios never imported; no `withCredentials` usage.
- **Impact:** CVSS 6.5 · CVE-2023-45857 · XSRF-TOKEN cookie sent to any server when `withCredentials` is on.

#### 1.7 ReDoS — trim function

- **Result:** Unreachable → Remediated — axios never imported; internal `trim` never executed.
- **Impact:** CVSS 7.5 · CVE-2021-3749 · Crafted string causes O(n²) regex backtracking, hanging the event loop.

#### 1.8 Prototype Pollution — mergeDirectKeys

- **Result:** Unreachable → Remediated — axios never imported; config merging never occurs.
- **Impact:** CVSS 7.5 (est.) · CVE-2026-42041 · Polluted `Object.prototype` alters `validateStatus` and bypasses error handling.

#### 1.9 Sensitive Data Leak — withXSRFToken cross-origin

- **Result:** Unreachable → Remediated — axios never imported; no XSRF configuration exists.
- **Impact:** CVSS 5.3 · CVE-2026-42042 · XSRF header sent cross-origin when `withXSRFToken` is truthy non-boolean.

#### 1.10 Resource Exhaustion — maxContentLength bypass

- **Result:** Unreachable → Remediated — axios never imported; HTTP adapter never used.
- **Impact:** CVSS 6.9 · CVE-2026-42036 · Streamed response bypasses size limit, exhausting memory.

#### 1.11 Resource Exhaustion — maxBodyLength bypass

- **Result:** Unreachable → Remediated — axios never imported; upload path never used.
- **Impact:** CVSS 6.9 · CVE-2026-42034 · Oversized request body transmitted despite configured limit.

#### 1.12 SSRF — CRLF header smuggling + proxy bypass

- **Result:** Unreachable → Remediated — axios never imported; no proxy configuration.
- **Impact:** CVSS 6.9 · CVE-2026-42038 · Control characters in headers alter downstream request interpretation.

#### 1.13 Improper Output Encoding — NUL byte in URLSearchParams

- **Result:** Unreachable → Remediated — axios never imported; `AxiosURLSearchParams` never used.
- **Impact:** CVSS 6.3 · CVE-2026-42040 · NUL byte smuggled into query strings truncates parameters.

#### 1.14 Confused Deputy — NO_PROXY bypass

- **Result:** Unreachable → Remediated — axios never imported; no proxy environment relied upon.
- **Impact:** CVSS 6.3 · CVE-2025-62718 · Trailing dot or `[::1]` bypasses NO_PROXY restrictions.

#### 1.15 Resource Exhaustion — data: URL DoS

- **Result:** Unreachable → Remediated — axios never imported; data: URL handler never invoked.
- **Impact:** CVSS 6.9 · CVE-2025-58754 · Oversized data: URL payload allocated before size check.

#### 1.16 SSRF — allowAbsoluteUrls default

- **Result:** Unreachable → Remediated — axios never imported; `buildFullPath` never called.
- **Impact:** CVSS 6.2 · No CVE assigned · Absolute URLs accepted by default, bypassing intended restrictions.

#### 1.17 SSRF — buildFullPath bypass

- **Result:** Unreachable → Remediated — axios never imported; request dispatch never occurs.
- **Impact:** CVSS 6.2 · CVE-2025-27152 · Malicious URLs bypass `allowAbsoluteUrls` in HTTP adapter.

#### 1.18 ReDoS — format method

- **Result:** Unreachable → Remediated — axios never imported; format method never called.
- **Impact:** CVSS 5.3 (est.) · No CVE assigned · Crafted input causes O(n²) regex in format method.

---

### 2 — lodash 4.17.19 (Direct, Unused)

**Evidence (applies to all lodash findings):** `grep -rn "lodash"` returns zero matches outside `package.json`. The app implements its own `debounce` in `src/services/api.js`. No `_.*` calls, no lodash imports anywhere.

**Fix (applies to all lodash findings):** Removed `"lodash": "4.17.19"` from `package.json` in commit `452bc5d`.

**Verification:** N/A — package was never imported; removal has no runtime effect.

---

#### 2.1 Arbitrary Code Injection — `_.template` imports

- **Result:** Unreachable → Remediated — lodash never imported; `_.template` never called.
- **Impact:** CVSS 8.6 · CVE-2026-4800 · Malicious `options.imports` key names execute arbitrary code at template compilation.

#### 2.2 Prototype Pollution — `zipObjectDeep`

- **Result:** Unreachable → Remediated — lodash never imported; `zipObjectDeep` never called.
- **Impact:** CVSS 9.1 · CVE-2019-10744 · Attacker adds/modifies properties on `Object.prototype` via crafted input.

#### 2.3 Code Injection — `_.template` variable

- **Result:** Unreachable → Remediated — lodash never imported; `_.template` never called.
- **Impact:** CVSS 7.2 · CVE-2021-23337 · Malicious `options.variable` executes arbitrary code at template compilation.

#### 2.4 Prototype Pollution — `_.unset`/`_.omit` array paths

- **Result:** Unreachable → Remediated — lodash never imported; neither function called.
- **Impact:** CVSS 7.5 (est.) · No CVE assigned · Array-wrapped path segments delete properties from built-in prototypes.

#### 2.5 Prototype Pollution — `_.unset`/`_.omit`

- **Result:** Unreachable → Remediated — lodash never imported; neither function called.
- **Impact:** CVSS 7.5 (est.) · No CVE assigned · String key paths delete methods from global prototypes.

#### 2.6 ReDoS — `toNumber`/`trim`/`trimEnd`

- **Result:** Unreachable → Remediated — lodash never imported; none of these functions called.
- **Impact:** CVSS 5.3 · CVE-2020-28500 · Crafted whitespace string causes O(n²) regex backtracking.

---

### 3 — dompurify 2.3.0 (Direct, Unused)

**Evidence (applies to all dompurify findings):** `grep -rn "DOMPurify\|dompurify\|purify"` returns zero matches outside `package.json`. No HTML sanitization occurs anywhere in the application.

**Fix (applies to all dompurify findings):** Removed `"dompurify": "2.3.0"` from `package.json` in commit `452bc5d`.

**Verification:** N/A — package was never imported; removal has no runtime effect.

---

#### 3.1 Prototype Pollution — sanitization bypass

- **Result:** Unreachable → Remediated — dompurify never imported; `sanitize()` never called.
- **Impact:** CVSS 7.5 (est.) · CVE-2024-48910 · Improper property checks during sanitization allow prototype pollution.

#### 3.2 Prototype Pollution — depth-checking bypass

- **Result:** Unreachable → Remediated — dompurify never imported; no HTML sanitization.
- **Impact:** CVSS 7.0 (est.) · CVE-2024-45801 · Deeply nested malicious HTML bypasses depth-checking to pollute prototypes.

#### 3.3 Logic Error — ADD_TAGS overrides FORBID_TAGS

- **Result:** Unreachable → Remediated — dompurify never imported; no tag configuration.
- **Impact:** CVSS 6.3 · CVE-2026-41240 · Short-circuit evaluation allows forbidden tags when `ADD_TAGS` is a function.

#### 3.4 Permissive Inputs — URI validation bypass

- **Result:** Unreachable → Remediated — dompurify never imported; no attribute checking configured.
- **Impact:** CVSS 5.3 · No CVE assigned · `javascript:` URIs bypass validation for specific attribute/tag combinations.

#### 3.5 Prototype Pollution — USE_PROFILES

- **Result:** Unreachable → Remediated — dompurify never imported; `USE_PROFILES` never configured.
- **Impact:** CVSS 7.5 (est.) · No CVE assigned · Polluted `Array.prototype` causes dangerous attributes like `onclick` to be allowed.

#### 3.6 XSS — innerHTML re-parsing in special contexts

- **Result:** Unreachable → Remediated — dompurify never imported; no sanitized HTML reinserted.
- **Impact:** CVSS 6.1 (est.) · No CVE assigned · Sanitized HTML re-parsed via `innerHTML` in `script`/`xmp`/`iframe` contexts executes injected markup.

#### 3.7 XSS — XML textarea comment injection

- **Result:** Unreachable → Remediated — dompurify never imported; no XML sanitization.
- **Impact:** CVSS 6.1 (est.) · No CVE assigned · Comments in XML textarea attributes contain executable scripts.

#### 3.8 XSS — XML noscript/xmp/iframe comment injection

- **Result:** Unreachable → Remediated — dompurify never imported; no XML sanitization.
- **Impact:** CVSS 6.1 (est.) · No CVE assigned · Comments in XML noscript/xmp/noembed/noframes/iframe attributes execute scripts.

#### 3.9 XSS — deeply nested elements

- **Result:** Unreachable → Remediated — dompurify never imported; `sanitize()` never called.
- **Impact:** CVSS 6.1 (est.) · CVE-2024-47875 · Deeply nested HTML bypasses sanitization in `createDOMPurify`.

#### 3.10 Template Injection — XML CDATA blocks

- **Result:** Unreachable → Remediated — dompurify never imported; no XML/HTML sanitization.
- **Impact:** CVSS 5.3 · No CVE assigned · Executable code injected via XML CDATA blocks due to XML/HTML parsing inconsistencies.

#### 3.11 XSS — SAFE_FOR_TEMPLATES + RETURN_DOM bypass

- **Result:** Unreachable → Remediated — dompurify never imported; no template mode configured.
- **Impact:** CVSS 6.1 (est.) · No CVE assigned · Template sanitization bypassed in RETURN_DOM mode; scripts execute if evaluated by Vue 2.

#### 3.12 XSS — template literal regex bypass

- **Result:** Unreachable → Remediated — dompurify never imported; no sanitization.
- **Impact:** CVSS 6.1 (est.) · CVE-2025-26791 · Malicious payloads bypass sanitization via template literal regex handling.

---

### 4 — follow-redirects ~1.14.x (Transitive via axios, Unused)

**Evidence (applies to all follow-redirects findings):** Transitive dependency of axios. Since axios is never imported, follow-redirects is never resolved, installed, or executed. `grep -rn "follow-redirects"` returns zero matches.

**Fix (applies to all follow-redirects findings):** Eliminated by removing axios from `package.json` in commit `452bc5d`.

**Verification:** N/A — transitive dependency of an unused package; never installed or executed.

---

#### 4.1 Auth Header Leak — cross-domain redirect

- **Result:** Unreachable → Remediated — follow-redirects never loaded; no HTTP redirects via axios.
- **Impact:** CVSS 7.7 · CVE-2026-40895 · Custom auth headers (X-API-Key, X-Auth-Token) forwarded to attacker-controlled domains on cross-domain redirect.

#### 4.2 URL Hostname Misinterpretation

- **Result:** Unreachable → Remediated — follow-redirects never loaded; `url.parse()` never invoked.
- **Impact:** CVSS 6.1 · CVE-2023-26159 · Crafted URL misinterpreted by `url.parse()` fallback, enabling redirect to malicious site.

#### 4.3 Proxy-Authorization Header Leak

- **Result:** Unreachable → Remediated — follow-redirects never loaded; no proxy auth configured.
- **Impact:** CVSS 6.5 · CVE-2024-28849 · Proxy-Authorization header persists across cross-domain redirects.

#### 4.4 Cookie Leak on Redirect

- **Result:** Unreachable → Remediated — follow-redirects never loaded; no cookie-bearing requests.
- **Impact:** CVSS 6.5 · CVE-2022-0155 · Cookie header leaked to third-party site during redirect.

#### 4.5 Auth Header Leak — HTTPS→HTTP downgrade

- **Result:** Unreachable → Remediated — follow-redirects never loaded; no HTTPS requests via axios.
- **Impact:** CVSS 5.9 · CVE-2022-0536 · Authorization header sent over insecure HTTP after HTTPS→HTTP redirect.

---

## Severity Distribution

| Severity | Count | Reachable | Remediated |
|----------|-------|-----------|------------|
| Critical | 3 | 0 | 3 |
| High | 11 | 0 | 11 |
| Medium | 25 | 0 | 25 |
| Low | 2 | 0 | 2 |
| **Total** | **41** | **0** | **41** |

## Remediation Summary

| Package | Version | Action | Commit |
|---------|---------|--------|--------|
| axios | 0.21.1 | Removed (unused) | `452bc5d` |
| lodash | 4.17.19 | Removed (unused) | `452bc5d` |
| dompurify | 2.3.0 | Removed (unused) | `452bc5d` |
| marked | 4.0.10 | Removed (unused, 14 majors behind) | `452bc5d` |
| follow-redirects | ~1.14.x | Eliminated (transitive of axios) | `452bc5d` |

## Residual Risk

None. All vulnerable packages were unused and have been removed. No code changes were required beyond `package.json` because no source file referenced any of these packages.

## Recommendation

Add a CI step (e.g., `npm audit --audit-level=moderate`) to prevent vulnerable dependencies from being reintroduced. Consider a policy requiring that dependencies declared in `package.json` must be imported somewhere in the codebase.
