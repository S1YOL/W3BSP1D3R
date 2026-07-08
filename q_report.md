# W3BSP1D3R — Scan Report

```
  W3BSP1D3R  |  Web Vulnerability Scanner  |  v3.0.0-beta  |  by S1YOL
```

| | |
|---|---|
| **Target** | `http://127.0.0.1:8099` |
| **Scan Type** | full |
| **Started** | 2026-07-08T05:00:59.807653+00:00 |
| **Finished** | 2026-07-08T05:01:08.251415+00:00 |
| **Duration** | 8.4s |

---

## Executive Summary

> ### 🔴 Overall Risk Rating: **CRITICAL**

This assessment tested **322** parameter(s) across **3** page(s) and identified **11** finding(s): 1 critical, 1 high, 7 medium, 2 low.

| Metric | Value |
|--------|-------|
| Pages Crawled | 3 |
| Forms Discovered | 2 |
| Parameters Tested | 322 |
| Total Findings | **11** |

### Severity Breakdown

| Severity | Count | Risk |
|----------|-------|------|
| 🔴 **CRITICAL** | 1 | Immediate exploitation risk — database compromise, RCE, auth bypass |
| 🟠 **HIGH** | 1 | Significant impact — session hijack, data exfiltration |
| 🟡 **MEDIUM** | 7 | Moderate risk — requires additional conditions to exploit |
| 🔵 **LOW** | 2 | Low impact — informational, defence-in-depth improvements |

### Detection Confidence

_How certain each finding is. Prioritise **Certain** findings; manually review **Tentative** ones before acting._

| Confidence | Count | Meaning |
|------------|-------|---------|
| Certain | 2 | Deterministic proof (e.g. reflected payload, DB error) |
| Firm | 0 | Strong heuristic, confirmed with a second request |
| Tentative | 9 | Heuristic only — manual verification advised |

---

## Findings

_11 vulnerabilities found, sorted by severity._

### Finding #1 — SQL Injection (Error-Based)

**Severity:** 🔴 **CRITICAL**  
**Confidence:** Certain  
**URL:** `http://127.0.0.1:8099/search?q=%27`  
**Parameter:** `q`  
**Method:** `GET`  
**Classification:** CWE: `CWE-89` · OWASP: `A03:2021 Injection`  
**Timestamp:** 2026-07-08T05:01:05.989444+00:00  

#### Proof-of-Concept Payload

```
'
```

#### Evidence

> DB error signature 'you have an error in your sql syntax' in response: …You have an error in your SQL syntax near '''…

#### Remediation

> Use parameterised queries (prepared statements) — NEVER concatenate user input into SQL strings. Validate and whitelist input types. Apply least-privilege database accounts. Enable a WAF for defence-in-depth. Ref: OWASP SQL Injection Prevention Cheat Sheet.

---

### Finding #2 — Cross-Site Scripting (Reflected)

**Severity:** 🟠 **HIGH**  
**Confidence:** Certain  
**URL:** `http://127.0.0.1:8099/search?q=%3Cscript%3Ealert%28%27XSSTESTBA128B0A%27%29%3C%2Fscript%3E`  
**Parameter:** `q`  
**Method:** `GET`  
**Classification:** CWE: `CWE-79` · OWASP: `A03:2021 Injection`  
**Timestamp:** 2026-07-08T05:01:04.269643+00:00  

#### Proof-of-Concept Payload

```
<script>alert('XSSTESTBA128B0A')</script>
```

#### Evidence

> Marker 'XSSTESTBA128B0A' reflected unencoded: …L syntax near '<script>alert('XSSTESTBA128B0A')</script>'…

#### Remediation

> Encode all user-supplied output using HTML entity encoding before rendering (e.g. use htmlspecialchars() in PHP, Jinja2 auto-escaping in Python, React JSX). Implement a strict Content-Security-Policy (CSP) header. Validate input server-side — reject or sanitise unexpected characters. Ref: OWASP XSS Prevention Cheat Sheet.

---

### Finding #3 — Cross-Site Request Forgery (CSRF)

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/login`  
**Parameter:** `csrf`  
**Method:** `POST`  
**Classification:** CWE: `CWE-352` · OWASP: `A08:2021 Software and Data Integrity Failures`  
**Timestamp:** 2026-07-08T05:00:59.830509+00:00  

#### Proof-of-Concept Payload

```
Observed token value: 'x'
```

#### Evidence

> CSRF token field 'csrf' found but has weaknesses: Token is too short (1 chars < 16 required) | Token value appears static or predictable (all same char, sequential, or very short)

#### Remediation

> The CSRF token present appears weak (too short, static, or in a GET param). Replace with a cryptographically random per-session token (min 128-bit / 16 bytes). Regenerate the token on each login and store it server-side for validation. Ref: OWASP CSRF Prevention Cheat Sheet.

---

### Finding #4 — Missing/Weak Security Header

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/`  
**Parameter:** `HTTP Response Headers`  
**Method:** `GET`  
**Classification:** CWE: `CWE-693` · OWASP: `A05:2021 Security Misconfiguration`  
**Timestamp:** 2026-07-08T05:00:59.919338+00:00  

#### Proof-of-Concept Payload

```
(header inspection — no payload sent)
```

#### Evidence

> Missing Content-Security-Policy (CSP): No CSP header found. CSP prevents XSS by declaring approved content sources. Set a strict policy.

#### Remediation

> Configure all recommended security headers in your web server or application. Validate your headers at securityheaders.com. Ref: OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/

---

### Finding #5 — Missing/Weak Security Header

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/search?q=hello`  
**Parameter:** `HTTP Response Headers`  
**Method:** `GET`  
**Classification:** CWE: `CWE-693` · OWASP: `A05:2021 Security Misconfiguration`  
**Timestamp:** 2026-07-08T05:00:59.958926+00:00  

#### Proof-of-Concept Payload

```
(header inspection — no payload sent)
```

#### Evidence

> Missing Content-Security-Policy (CSP): No CSP header found. CSP prevents XSS by declaring approved content sources. Set a strict policy.

#### Remediation

> Configure all recommended security headers in your web server or application. Validate your headers at securityheaders.com. Ref: OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/

---

### Finding #6 — Missing/Weak Security Header

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/page2`  
**Parameter:** `HTTP Response Headers`  
**Method:** `GET`  
**Classification:** CWE: `CWE-693` · OWASP: `A05:2021 Security Misconfiguration`  
**Timestamp:** 2026-07-08T05:00:59.969175+00:00  

#### Proof-of-Concept Payload

```
(header inspection — no payload sent)
```

#### Evidence

> Missing Content-Security-Policy (CSP): No CSP header found. CSP prevents XSS by declaring approved content sources. Set a strict policy.

#### Remediation

> Configure all recommended security headers in your web server or application. Validate your headers at securityheaders.com. Ref: OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/

---

### Finding #7 — Technology Stack Detected

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099`  
**Parameter:** `Multiple indicators`  
**Method:** `GET`  
**Classification:** CWE: `N/A`  
**Timestamp:** 2026-07-08T05:01:02.339699+00:00  

#### Proof-of-Concept Payload

```
Header analysis + HTML fingerprinting + path probing
```

#### Evidence

> Detected 1 technologies: Server header: Server: BaseHTTP/0.6 Python/3.14.6

#### Remediation

> Remove or obscure technology identifiers from HTTP headers (Server, X-Powered-By). Disable version disclosure in your web server and framework configuration. Apache: ServerTokens Prod, ServerSignature Off. Nginx: server_tokens off. PHP: expose_php = Off in php.ini. While security through obscurity alone is insufficient, reducing information disclosure makes reconnaissance harder.

---

### Finding #8 — Clickjacking — No Framing Protection

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/`  
**Parameter:** `X-Frame-Options / CSP frame-ancestors`  
**Method:** `GET`  
**Classification:** CWE: `CWE-1021`  
**Timestamp:** 2026-07-08T05:01:04.639036+00:00  

#### Proof-of-Concept Payload

```
Check response headers
```

#### Evidence

> Neither X-Frame-Options nor CSP frame-ancestors header is set. The page can be embedded in an iframe on any malicious site.

#### Remediation

> Add X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed within your own site). Better yet, use CSP: Content-Security-Policy: frame-ancestors 'self'. This prevents your pages from being embedded in attacker-controlled iframes.

---

### Finding #9 — Missing Rate Limiting (login form)

**Severity:** 🟡 **MEDIUM**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/login`  
**Parameter:** `Login form`  
**Method:** `POST`  
**Classification:** CWE: `CWE-307`  
**Timestamp:** 2026-07-08T05:01:04.868954+00:00  

#### Proof-of-Concept Payload

```
10 rapid login attempts
```

#### Evidence

> Submitted 10 rapid login attempts to http://127.0.0.1:8099/login without rate limiting. Credential brute force attacks are possible.

#### Remediation

> Implement rate limiting on login forms. After 5 failed attempts, require CAPTCHA or lock the account temporarily. Log all failed login attempts for monitoring.

---

### Finding #10 — Autocomplete Enabled on Sensitive Field

**Severity:** 🔵 **LOW**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/`  
**Parameter:** `password field`  
**Method:** `GET`  
**Classification:** CWE: `N/A`  
**Timestamp:** 2026-07-08T05:01:04.141128+00:00  

#### Proof-of-Concept Payload

```
Check form HTML
```

#### Evidence

> Password field without autocomplete='off': <input type="password" name="password">

#### Remediation

> Add autocomplete='off' or autocomplete='new-password' to sensitive form fields (passwords, credit cards, SSNs) to prevent browsers from caching credentials.

---

### Finding #11 — Autocomplete Enabled on Sensitive Field

**Severity:** 🔵 **LOW**  
**Confidence:** Tentative  
**URL:** `http://127.0.0.1:8099/page2`  
**Parameter:** `password field`  
**Method:** `GET`  
**Classification:** CWE: `N/A`  
**Timestamp:** 2026-07-08T05:01:04.519248+00:00  

#### Proof-of-Concept Payload

```
Check form HTML
```

#### Evidence

> Password field without autocomplete='off': <input type="password" name="password">

#### Remediation

> Add autocomplete='off' or autocomplete='new-password' to sensitive form fields (passwords, credit cards, SSNs) to prevent browsers from caching credentials.

---

---

## Remediation Summary

The following fixes are recommended, grouped by vulnerability type:

### SQL Injection (Error-Based)

Use parameterised queries (prepared statements) — NEVER concatenate user input into SQL strings. Validate and whitelist input types. Apply least-privilege database accounts. Enable a WAF for defence-in-depth. Ref: OWASP SQL Injection Prevention Cheat Sheet.

### Cross-Site Scripting (Reflected)

Encode all user-supplied output using HTML entity encoding before rendering (e.g. use htmlspecialchars() in PHP, Jinja2 auto-escaping in Python, React JSX). Implement a strict Content-Security-Policy (CSP) header. Validate input server-side — reject or sanitise unexpected characters. Ref: OWASP XSS Prevention Cheat Sheet.

### Cross-Site Request Forgery (CSRF)

The CSRF token present appears weak (too short, static, or in a GET param). Replace with a cryptographically random per-session token (min 128-bit / 16 bytes). Regenerate the token on each login and store it server-side for validation. Ref: OWASP CSRF Prevention Cheat Sheet.

### Missing/Weak Security Header

Configure all recommended security headers in your web server or application. Validate your headers at securityheaders.com. Ref: OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/

### Technology Stack Detected

Remove or obscure technology identifiers from HTTP headers (Server, X-Powered-By). Disable version disclosure in your web server and framework configuration. Apache: ServerTokens Prod, ServerSignature Off. Nginx: server_tokens off. PHP: expose_php = Off in php.ini. While security through obscurity alone is insufficient, reducing information disclosure makes reconnaissance harder.

### Clickjacking — No Framing Protection

Add X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed within your own site). Better yet, use CSP: Content-Security-Policy: frame-ancestors 'self'. This prevents your pages from being embedded in attacker-controlled iframes.

### Missing Rate Limiting (login form)

Implement rate limiting on login forms. After 5 failed attempts, require CAPTCHA or lock the account temporarily. Log all failed login attempts for monitoring.

### Autocomplete Enabled on Sensitive Field

Add autocomplete='off' or autocomplete='new-password' to sensitive form fields (passwords, credit cards, SSNs) to prevent browsers from caching credentials.

---

## Legal Disclaimer

> **⚠️ AUTHORISED TESTING ONLY**  
> This report was generated by an automated vulnerability scanner.  
> The scanner MUST only be used against applications you own or have  
> **explicit written permission** to test.  
> Unauthorised scanning is illegal under the Computer Fraud and Abuse Act  
> (CFAA, 18 U.S.C. § 1030) and equivalent laws in other jurisdictions.  
> I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP. Scanning without authorization is a federal crime under CFAA (18 U.S.C. § 1030).  

_Report generated by [W3BSP1D3R](https://github.com/siyol/web-vuln-scanner) — by S1YOL_
