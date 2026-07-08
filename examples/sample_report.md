# STRYX Security Scan Report

**Target:** http://localhost:8000
**Findings:** 3

## Summary

- **CRITICAL:** 1
- **HIGH:** 1
- **MEDIUM:** 1

## Findings

### 1. [CRITICAL] Unauthenticated access to /admin

**Endpoint:** http://localhost:8000/admin
**CWE:** CWE-306
**OWASP:** A07:2021 - Identification and Authentication Failures
**Scanner:** auth
**Confidence:** 70%

**Description:** The endpoint /admin is accessible without any authentication. This may expose sensitive data or administrative functions.

**Remediation:** Implement authentication middleware to protect this endpoint.

**Evidence:**
- Method: `GET`
- URL: `http://localhost:8000/admin`
- Status: `200`
- Response snippet:
```
<html>
<body>
<h1>Admin Panel</h1>
<p>Welcome, Administrator</p>
</body>
</html>
```

---

### 2. [HIGH] Potential IDOR at /api/users/1

**Endpoint:** http://localhost:8000/api/users/1
**CWE:** CWE-639
**OWASP:** A01:2021 - Broken Access Control
**Scanner:** authorization
**Confidence:** 75%

**Description:** The endpoint /api/users/1 returns user data. Changing the ID parameter may allow accessing other users' data.

**Remediation:** Implement proper authorization checks. Verify the authenticated user owns the requested resource.

**Evidence:**
- Method: `GET`
- URL: `http://localhost:8000/api/users/1`
- Status: `200`
- Response snippet:
```
{"id": "1", "name": "Alice", "email": "alice@example.com", "password": "secret123"}
```

---

### 3. [MEDIUM] CORS misconfiguration: reflects Origin 'https://evil.com'

**Endpoint:** http://localhost:8000
**CWE:** CWE-942
**OWASP:** A05:2021 - Security Misconfiguration
**Scanner:** cors
**Confidence:** 80%

**Description:** The server reflects the Origin header 'https://evil.com' in Access-Control-Allow-Origin.

**Remediation:** Whitelist specific trusted origins. Never reflect arbitrary origins when credentials are allowed.

**Evidence:**
- Method: `GET`
- URL: `http://localhost:8000`
- Status: `200`
