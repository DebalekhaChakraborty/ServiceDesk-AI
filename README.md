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
mode reports lock state as unknown rather than claiming the account is unlocked. A
real AD DS connector is still required for lock inspection and unlock.

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
