# NIST Cybersecurity Response Guidance

This corpus extends the local NIST reference set for monitoring and incident handling.

## DE.AE-1 Anomalous Events Are Detected

Use this section when logs show clear deviations from baseline behavior or repeated suspicious actions.

Relevant signals:
- anomalous events
- repeated suspicious actions
- outlier behavior
- alerting

## DE.CM-1 Monitoring Processes and Procedures

Use this section when the event shows abnormal device behavior, repeated alerts, or suspicious operational changes.

Relevant signals:
- device offline
- frequent state change
- unusual operational events
- monitoring and alerting

## DE.CM-7 Monitoring for Unauthorized Connections, Devices, and Software

Use this section when the same source hits many endpoints or shows active probing behavior.

Relevant signals:
- active scanning
- suspicious connections
- abnormal access patterns
- monitoring for unauthorized software

## PR.AC-4 Access Permissions and Authorizations Managed

Use this section when the log shows time-of-day anomalies or access-control concerns.

Relevant signals:
- off-hours access
- authorization anomalies
- access permissions
- privilege review

## RS.MI-1 Incidents Are Contained

Use this section when suspicious activity needs to be isolated, blocked, or rate limited.

Relevant signals:
- containment
- blocking suspicious IPs
- isolating affected accounts
- limiting exposure

## RS.RP-1 Response Plan Is Executed

Use this section when the event warrants a repeatable incident response workflow.

Relevant signals:
- incident response
- escalation
- containment
- remediation
