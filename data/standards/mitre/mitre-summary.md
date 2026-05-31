# MITRE ATT&CK Security Guidance

This corpus provides a compact ATT&CK reference for log analysis.

## T1110 Brute Force

Use this section when logs show repeated failed logins, password guessing, or success after failures.

Relevant signals:
- brute force
- password guessing
- authentication failure bursts
- success after repeated failures

## T1087 Account Discovery

Use this section when the same source tries multiple accounts or enumerates usernames.

Relevant signals:
- account enumeration
- username probing
- repeated login attempts across many accounts

## T1595 Active Scanning

Use this section when the same source probes many URLs or scans endpoints.

Relevant signals:
- web scanning
- active scanning
- path enumeration
- reconnaissance

## T1190 Exploit Public-Facing Application

Use this section when the request contains exploit payloads against a public endpoint.

Relevant signals:
- SQL injection
- cross-site scripting
- directory traversal
- command injection

## T1059 Command and Scripting Interpreter

Use this section when a request contains shell metacharacters or command execution payloads.

Relevant signals:
- command injection
- shell execution
- powershell
- bash -c

## T1005 Data from Local System

Use this section when logs suggest reading sensitive files from a local host.

Relevant signals:
- /etc/passwd
- win.ini
- web.config
- .ssh/id_rsa
