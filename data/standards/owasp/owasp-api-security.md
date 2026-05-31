# OWASP API Security Guidance

This corpus extends the local reference set for API-focused log analysis.

## API1 Broken Object Level Authorization

Use this section when API requests reach objects or records without the correct authorization decision.

Relevant signals:
- broken object level authorization
- unauthorized object access
- permission anomaly
- direct object reference

Recommended controls:
- object-level authorization checks
- deny by default
- server-side enforcement
- audit logging

## API2 Broken Authentication

Use this section when API requests show missing, weak, or bypassed authentication.

Relevant signals:
- broken authentication
- missing authentication
- login failures
- token validation

Recommended controls:
- strong token validation
- MFA where appropriate
- short-lived tokens
- auth monitoring

## API5 Broken Function Level Authorization

Use this section when a user reaches a privileged API action without the required role or scope.

Relevant signals:
- broken function level authorization
- privilege escalation
- permission anomaly
- forbidden access

Recommended controls:
- role checks
- scope checks
- server-side authorization
- least privilege

## API10 Unsafe Consumption of APIs

Use this section when the application calls downstream APIs unsafely or without validation.

Relevant signals:
- unsafe API consumption
- untrusted upstream data
- missing validation
- unexpected API errors

Recommended controls:
- validate upstream data
- schema checks
- circuit breakers
- monitoring

## API Logging and Monitoring

Use this section when requests look abnormal, repetitive, or crafted for probing.

Relevant signals:
- abnormal API calls
- sensitive endpoint probing
- repeated failures
- unauthorized connections

Recommended controls:
- alerting
- centralized logging
- rate limiting
- abuse detection
