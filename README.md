# ServiceDesk AI

## Account Access backend

Account Access defaults to the non-executing `AD_ACCOUNT_MODE=off` mode. Use the
repository's existing Microsoft Graph application credentials for real Microsoft
Entra user profile, `accountEnabled`, and enable-account operations:

```ini
AD_ACCOUNT_MODE=graph
```

Graph status reads relevant account metadata directly from `/users/{UPN}`. Microsoft
Graph does not expose a current AD DS lockout boolean on the user resource, so Graph
mode reports lock state as unknown rather than claiming the account is unlocked.
For authorized Account Access diagnosis, the backend also samples up to 20 sign-in
events from the previous 24 hours through `/auditLogs/signIns`. It returns sanitized
failure, application, and device evidence, including any error code `50053`, while
keeping the current lock state unknown and never selecting remediation from log
evidence alone.

Sign-in investigation requires the Microsoft Graph `AuditLog.Read.All` application
permission with administrator consent and an applicable Microsoft Entra ID P1/P2
license. If that permission or service is unavailable, account profile diagnosis
continues and reports the sign-in evidence limitation explicitly. A real AD DS
connector is still required for authoritative AD DS lock inspection and unlock.

The deterministic in-process backend is retained only as a unit-test seam. It has
no environment-driven per-user status lists and must not be used to represent live
directory state. Unlocking never enables an account, and enabling never clears
lockout.

### Account Access identity orchestration

Protected Account Access conversations use a deterministic controller rather than
letting the language model assemble privileged calls. Every diagnosis, recheck,
and action refreshes and binds:

- the session requester corroborated against the exact Microsoft Graph user;
- the exact target Graph user and the target's current Graph manager;
- registered-device inventories for both requester and target; and
- the canonical self-or-current-manager policy decision.

A successful empty registered-device list is valid. A failed device or manager
query stops the flow. Device registration is recorded as security context only;
it does not grant endpoint-remediation permission. Real Graph account tools and
password reset also require the controller's fresh verification ID, so a manually
sequenced policy call cannot bypass device evidence.

Diagnosis creates a short-lived target/action-bound offer. Confirmation accepts no
target, manager, device, or action arguments and must arrive in a later ADK user
invocation. After enablement, any follow-up unlock is a new offer requiring a new
confirmation.

The current portal supplies the requester through session persona state. Graph
corroboration verifies that the claimed UPN/object exists and matches, but it is not
a replacement for interactive user authentication. A production deployment must
populate that persona from validated Entra ID authentication claims at the backend
trust boundary.

## Amazon WorkSpaces Phase C

Phase C adds two cohesive, read-only diagnostics to the existing Service Desk
orchestrator: WorkSpaces login/access diagnosis and WorkSpaces session-performance
diagnosis. Named AWS WorkSpaces issues stay in the WorkSpaces domain; the login
diagnostic reuses the protected Phase B account-status controller only for the KB's
domain-account enabled/locked prerequisites.

### Modes and identity mapping

The safe default is non-executing:

```ini
AWS_WORKSPACES_MODE=off
```

Use `demo` only for deterministic offline tests and `aws` for real read-only AWS
calls. AWS failure never falls back to demo data.

```ini
AWS_WORKSPACES_MODE=aws
AWS_WORKSPACES_USER_MAP_PATH=/secure/local/path/workspaces_user_map.json
AWS_WORKSPACES_METRIC_LOOKBACK_MINUTES=30
```

Install the optional AWS dependency with:

```bash
python -m pip install -r requirements-aws-workspaces.txt
```

The mapping file must explicitly bind the authenticated Entra UPN to Region,
DirectoryId, and WorkSpaces UserName. The implementation does not strip the UPN
domain or assume both identities match. See
`examples/aws_workspaces_user_map.example.json`; never commit the customer mapping.
Phase C is self-service only, so a target UPN different from the authenticated
caller is rejected before AWS is queried.

`boto3` uses the standard AWS credential provider chain. Do not put access keys,
secret keys, or session tokens in the repository, mapping, fixtures, or logs.

For deterministic development:

```ini
AWS_WORKSPACES_MODE=demo
AWS_WORKSPACES_USER_MAP_PATH=/secure/local/path/workspaces_user_map.json
AWS_WORKSPACES_DEMO_FIXTURE_PATH=tests/fixtures/aws_workspaces_demo.json
```

Demo results identify their backend as `demo`; they are never represented as real
AWS observations.

### Required IAM reads

The AWS principal needs only these Phase C control-plane reads:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "workspaces:DescribeWorkspaces",
        "workspaces:DescribeWorkspacesConnectionStatus",
        "workspaces:DescribeWorkspaceDirectories",
        "ds:DescribeDirectories",
        "cloudwatch:GetMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

No AWS create, modify, start, stop, rebuild, restore, or terminate operation is
implemented or called.

### Diagnostic behavior and limitations

Login diagnosis reports assignment, WorkSpace state, connection state, Phase B
account prerequisites, internal registration comparison, directory-level
RADIUS/MFA configuration, and honest `not_verifiable` results. A directory-level
MFA result does not prove individual Okta or Symantec VIP enrollment. Standard AWS
APIs also do not expose the customer's exact inactivity-disable business policy.

Registration codes are held only long enough for an internal equality comparison
on an authorized reachable WorkSpaces client endpoint. They are never returned,
logged, persisted, ticketed, or included in fixtures. The remote WorkSpace
`ComputerName` is not treated as the local client endpoint and is never trusted as
a WinRM target.

Performance diagnosis queries recent `AWS/WorkSpaces` metrics for the real
WorkspaceId. It applies only the KB0019144 rule `InSessionLatency > 200 ms`; exactly
200 ms is not a breach. CPU, memory, disk, packet-loss, and retransmission values
are observations unless an SOP supplies a threshold. Missing CloudWatch data is
reported unavailable, never as zero.

KB0019144's “Disk Cleanup > Clean Up System Files” is not equivalent to the
existing temporary-file cleanup. Because the supplied KB does not authorize exact
cleanup categories, Phase C reports this remediation as `not_automatable` and does
not execute cleanup. The existing ServiceNow fallback can be offered.

### Real AWS portal validation

After installing `boto3`, configuring the read-only AWS credential chain, setting
`AWS_WORKSPACES_MODE=aws`, and creating the private mapping file, restart the
backend and use a fresh portal session for each scenario:

1. Send `I can't login to AWS WorkSpaces.` Confirm the response includes the real
   WorkspaceId, assignment, WorkSpace state, and connection state, with no password
   reset.
2. Map a directory user with no WorkSpace and send
   `I'm getting Not Authorized in WorkSpaces.` Confirm
   `WORKSPACE_NOT_ASSIGNED`, with no password or Windows action.
3. With one authorized reachable Windows client endpoint, run login diagnosis and
   confirm registration is only `pass`, `fail`, or `not_verifiable`; no registration
   code may appear in chat or logs.
4. Send `My AWS WorkSpace is freezing and lagging.` Confirm real recent
   InSessionLatency, CPU, memory, root/user disk, connection, packet-loss, and
   retransmission observations. If RTT exceeds 200 ms, confirm
   `HIGH_IN_SESSION_LATENCY` and the measured value.
5. After high latency, confirm the bot describes System File Cleanup as KB guidance
   and `not_automatable`; it must not execute `cleanup_temp_files` or use the remote
   WorkSpace ComputerName as a WinRM endpoint.
6. In a fresh session send `I can't access my account.` Confirm the existing Phase B
   Account Access flow runs and no AWS diagnosis occurs.
7. During a WorkSpaces login conversation send `Can you reset it?` Confirm the bot
   asks whether this means WorkSpaces-specific recovery or an independent enterprise
   AD reset and does not call `aad_reset_password` silently.
