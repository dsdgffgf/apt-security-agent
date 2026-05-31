# OWASP Security Guidance

This corpus is a compact local reference for log analysis and retrieval.

## A07 Identification and Authentication Failures

Use this section when the log shows failed logins, repeated authentication attempts, account guessing, or success after repeated failures.

Relevant signals:
- brute force
- account enumeration
- password spraying
- repeated failed login attempts

Recommended controls:
- multi-factor authentication
- rate limiting
- lockout policy
- alerting on repeated failures

## A03 Injection

Use this section when the log shows SQL injection, command injection, or XSS-style payloads in parameters or paths.

Relevant signals:
- SQL injection
- command injection
- cross-site scripting
- public-facing request tampering

Recommended controls:
- input validation
- parameterized queries
- output encoding
- WAF rules for known payloads

## A01 Broken Access Control

Use this section when the log shows directory traversal, sensitive file access, or unauthorized resource access.

Relevant signals:
- directory traversal
- sensitive file access
- unauthorized file download
- privilege abuse

Recommended controls:
- server-side access checks
- least privilege
- deny by default
- file path normalization

## API Security Top 10

Use this section when the log shows abnormal API calls, broken authentication, or authorization failures.

Relevant signals:
- broken authentication
- broken function level authorization
- broken object level authorization
- sensitive endpoint probing

Recommended controls:
- authorization checks on every request
- token validation
- endpoint-specific access control
- audit logging
