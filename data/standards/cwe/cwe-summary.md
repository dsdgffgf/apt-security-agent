# CWE Weakness Reference

This corpus is a compact local reference for log analysis and retrieval.

## CWE-89 SQL Injection

Use this section when the log shows SQL payloads, UNION-based probes, tautology bypasses, or stacked queries.

Relevant signals:
- SQL injection
- UNION SELECT
- tautology-based bypass
- stacked query attempts

Recommended controls:
- parameterized queries
- input validation
- least privilege
- prepared statements

## CWE-78 OS Command Injection

Use this section when the log shows shell metacharacters, command separators, or explicit command execution payloads.

Relevant signals:
- command injection
- shell metacharacters
- bash -c
- powershell

Recommended controls:
- allowlist command execution
- strict input validation
- escaping where unavoidable
- OS-level least privilege

## CWE-79 Cross-Site Scripting

Use this section when the log shows script tags, event handlers, or reflected payloads in request parameters.

Relevant signals:
- XSS
- cross-site scripting
- script tags
- event handlers

Recommended controls:
- output encoding
- context-aware sanitization
- CSP
- input validation

## CWE-22 Path Traversal

Use this section when the log shows ../ traversal, file probing, or direct sensitive path access.

Relevant signals:
- directory traversal
- ../
- /etc/passwd
- file path normalization

Recommended controls:
- canonicalize paths
- deny by default
- filesystem access checks
- least privilege

## CWE-307 Improper Restriction of Excessive Authentication Attempts

Use this section when the log shows repeated failed logins, password spraying, or brute-force behavior.

Relevant signals:
- brute force
- repeated failed login attempts
- password spraying
- authentication failure bursts

Recommended controls:
- rate limiting
- lockout policy
- MFA
- alerting on repeated failures

## CWE-203 Observable Discrepancy

Use this section when the same source probes multiple accounts or gets distinguishable authentication responses.

Relevant signals:
- account enumeration
- username probing
- observable discrepancy
- login response differences

Recommended controls:
- uniform error responses
- rate limiting
- MFA
- anomaly detection

## CWE-306 Missing Authentication for Critical Function

Use this section when a critical API or device function appears accessible without proper authentication.

Relevant signals:
- broken authentication
- missing authentication
- critical function access
- unauthorized control

Recommended controls:
- authentication on every critical function
- token validation
- access checks
- audit logging

## CWE-285 Improper Authorization

Use this section when a request reaches a function or object without the expected authorization decision.

Relevant signals:
- broken object level authorization
- broken function level authorization
- access denied
- permission anomaly

Recommended controls:
- server-side authorization checks
- least privilege
- deny by default
- object-level access control

## CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

Use this section when logs show sensitive file reads, secret leakage, or direct exposure of local data.

Relevant signals:
- sensitive file access
- unauthorized data exposure
- credential leakage
- secret disclosure

Recommended controls:
- data minimization
- access control
- secret redaction
- logging hygiene
