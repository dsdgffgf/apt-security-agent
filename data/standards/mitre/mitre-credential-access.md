# MITRE ATT&CK Credential and Access Guidance

This corpus extends the local ATT&CK reference set for authentication-focused log analysis.

## T1110 Brute Force

Use this section when logs show repeated failed logins, password guessing, or successful access after failures.

Relevant signals:
- brute force
- password guessing
- authentication failure bursts
- success after repeated failures

## T1078 Valid Accounts

Use this section when valid credentials appear to be reused for unauthorized or suspicious access.

Relevant signals:
- valid accounts
- successful login after failures
- suspicious authentication success
- off-hours access

## T1087 Account Discovery

Use this section when the same source tries many usernames or probes account validity.

Relevant signals:
- account enumeration
- username probing
- repeated login attempts across many accounts

## T1021.004 Remote Services: SSH

Use this section when SSH access is the primary transport for a suspicious login sequence.

Relevant signals:
- ssh login
- remote service access
- repeated SSH failures
- public IP SSH access

Recommended controls:
- MFA
- rate limiting
- lockout policy
- restricted remote access
