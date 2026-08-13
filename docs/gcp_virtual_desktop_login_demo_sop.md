# GCP Virtual Desktop PoC SOP — Login Diagnosis

This is a sanitized proof-of-concept procedure for a single-user Windows desktop
on Google Compute Engine. It is not a customer knowledge article and it does not
authorize infrastructure changes or password resets.

1. Validate that the authenticated caller has an explicit private mapping to a
   Compute Engine Windows virtual desktop.
2. Validate that the mapped virtual desktop exists and is running.
3. Validate that recent guest and RDP telemetry is available.
4. Review recent RDP connection, authentication, session, and disconnect events.
5. Review IAP/RDP access state where it can be determined safely.
6. Determine whether the issue is VM availability, RDP authentication/session,
   connectivity configuration, or not identifiable from available telemetry.
7. Escalate when no safe read-only diagnosis can determine the cause.

The procedure must not reset a password, start or stop a VM, modify a firewall,
change IAM, invoke generic Active Directory remediation, or select a VM supplied
through chat.
