# Employee Access Portal

A small, self-contained employee-facing web application whose sign-in is
authenticated by **Microsoft Entra ID** — the same tenant and the same user that
ServiceDesk AI already diagnoses and remediates.

Its entire job is to be a *real* application that a disabled account cannot log
into, so that Microsoft Entra account remediation can be demonstrated end to end
with visible, unfaked consequences.

**This application does not administer accounts.** It never calls Microsoft
Graph, never reads `accountEnabled`, and holds no directory privilege of any
kind. Account diagnosis and governed enablement remain entirely with the
existing ServiceDesk AI backend.

---

## 1. Architecture

Two independent systems that share one identity provider:

```
        Employee Access Portal                       ServiceDesk AI
        (this application)                           (existing, unchanged)

              Browser                                    Employee chat
                 |                                             |
                 | HTTPS                                       |
                 v                                             v
        +--------------------+                        +--------------------+
        |     Cloud Run      |                        |   ServiceDesk AI   |
        |  employee portal   |                        |   agent + tools    |
        +--------------------+                        +--------------------+
                 |                                             |
                 | OIDC authorization code flow                | Microsoft Graph
                 | (openid, profile, email)                    | (application permissions)
                 v                                             v
        +-------------------------------------------------------------------+
        |                        Microsoft Entra ID                          |
        |                    one tenant, one employee account                |
        +-------------------------------------------------------------------+
```

The portal only ever asks Entra one question — *"will you authenticate this
employee right now?"* — and believes only the answer it receives.
ServiceDesk AI separately reads and writes `accountEnabled` through Microsoft
Graph using its own application identity and its own authorization gate.

### What each side owns

| Concern | Employee Access Portal | ServiceDesk AI |
|---|---|---|
| Hosting | Cloud Run (GCP) | existing deployment |
| Authenticates the employee | **yes**, via Entra OIDC | no |
| Reads `accountEnabled` | **never** | yes, via Graph |
| Enables an account | **never** | yes, governed |
| Microsoft Graph privilege | **none** | application permissions |
| Identity provider | Microsoft Entra ID | Microsoft Entra ID |

### Points that customers usually ask about

- **Cloud Run / GCP IAM hosts the application.** GCP is infrastructure only. It
  makes no identity decision about the employee.
- **Microsoft Entra authenticates the employee.** Application access is
  protected by Entra, not by GCP IAM. The Cloud Run service is deliberately
  publicly invocable at the transport layer so that Microsoft can redirect the
  browser back to it; the first thing an anonymous visitor can reach is the
  Microsoft sign-in page.
- **The GCP VM does not need to be Entra joined.** Nothing in this flow depends
  on device join, domain join, or any on-premises directory. It is a browser
  doing OIDC against Microsoft.
- **The portal does not administer users.** It has no Graph client, no Graph
  scope, and no directory write path.
- **ServiceDesk AI performs the governed Graph remediation**, with its existing
  identity verification, policy check, and explicit user confirmation.
- **Both systems operate against the same Entra tenant and user**, which is what
  makes the demonstration real rather than staged.

---

## 2. File tree

```
employee_access_portal/
├── Dockerfile                    Cloud Run container (node:22-alpine, non-root)
├── .dockerignore
├── .env.example                  local development template, placeholders only
├── .gitignore
├── package.json
├── package-lock.json
├── public/
│   └── styles.css                corporate styling, no external assets
├── scripts/
│   └── deploy_cloud_run.sh       bootstrap-secrets | phase-a | phase-b
├── src/
│   ├── app.js                    Express app factory, security headers
│   ├── server.js                 container entrypoint, PORT, SIGTERM
│   ├── config.js                 environment validation, single-tenant guard
│   ├── entra.js                  MSAL Node: auth code + PKCE, claim validation
│   ├── session.js                AES-256-GCM sealed stateless cookies
│   ├── logger.js                 minimal, token-free structured logging
│   ├── routes/
│   │   ├── health.js             GET /healthz
│   │   ├── auth.js               sign-in, callback, verify, sign-out, error
│   │   └── portal.js             landing page, protected workspace
│   └── views/
│       ├── layout.js             HTML shell + escaping
│       ├── landing.js            public sign-in page
│       ├── workspace.js          authenticated workspace
│       └── authError.js          friendly authentication failure page
└── test/
    ├── helpers.js
    ├── health.test.js
    ├── auth-callback.test.js
    ├── verify-access.test.js
    ├── workspace.test.js
    ├── security-posture.test.js
    └── entra-client.test.js
```

## 3. Dependencies

Three runtime dependencies, deliberately:

| Package | Version | Why |
|---|---|---|
| `express` | ^5.2.1 | HTTP routing |
| `@azure/msal-node` | ^5.5.0 | Microsoft-supported OIDC/OAuth client |
| `cookie-parser` | ^1.4.7 | cookie reading |

Development only: `supertest` (^7.2.2). Tests run on the Node.js built-in
runner, so there is no test framework dependency.

There is intentionally **no** Microsoft Graph SDK, no HTTP client, and no
session-store dependency. `npm audit` reports 0 vulnerabilities.

---

## 4. Routes

| Route | Auth | Behaviour |
|---|---|---|
| `GET /` | public | landing page; an authenticated employee is sent to `/workspace` |
| `GET /auth/signin` | public | creates state/nonce/PKCE, redirects to Entra |
| `GET /auth/redirect` | public | authorization response (configured `response_mode=query`) |
| `POST /auth/redirect` | public | same handler, for `form_post` tenants |
| `GET /workspace` | **protected** | employee workspace; redirects to sign-in without a valid session |
| `POST /auth/verify` | **protected + CSRF** | **Verify Corporate Access** — clears local session, forces `prompt=login` |
| `POST /auth/signout` | **protected + CSRF** | clears the local application session |
| `GET /auth/error` | public | branded authentication failure page |
| `GET /healthz` | public | `200 {"status":"ok",...}`, no Entra round trip |

> **Cloud Run caveat.** Google's frontend reserves the bare path `/healthz` on
> `*.run.app` and answers it with its own 404 without forwarding the request to
> the container. The application serves `/healthz` correctly — Cloud Run's own
> startup and liveness probes reach the container directly and are unaffected —
> but an *external* check over the public hostname must use the trailing-slash
> form `/healthz/`, which Express matches to the same route. The deploy script
> does this automatically.

### Verify Corporate Access

This is the route the demonstration depends on. Pressing the button causes the
portal to:

1. clear its own authenticated session cookie;
2. discard all locally retained identity state;
3. generate a fresh `state`, `nonce`, and PKCE verifier;
4. begin a new Entra authorization request;
5. set **`prompt=login`**;
6. require Microsoft Entra to authenticate the employee again.

There is no local account-status API, no cached account state, and no call to
ServiceDesk AI. If Entra refuses, `/workspace` cannot render. If Microsoft
returns an OAuth error, the portal shows:

> **Corporate access could not be verified.**
> Your organizational identity did not complete authentication.
> Please contact the Service Desk if you require assistance.

with an optional sanitized Microsoft error code as a technical reference. The
portal never invents a reason — it has no directory visibility, so it cannot
and does not claim "your account is disabled" unless Microsoft said so.

---

## 5. Security model

**Authentication**
- Authorization code flow with PKCE (`S256`). The implicit flow is never used.
- Single-tenant authority only: `https://login.microsoftonline.com/<tenant-id>`.
  `common`, `organizations`, and `consumers` are rejected at startup.
- Cryptographically random `state` (32 bytes) and `nonce` (32 bytes) per
  request, never reused.
- `state` validated with a constant-time comparison on callback.
- `nonce` validated against the returned ID token claims.
- `tid` re-validated on the ID token, so a token from another tenant is refused.

**Scopes**
- The portal requests `openid profile email` and nothing else.
- No administrative Microsoft Graph scope is ever requested.
- MSAL Node appends `offline_access` to authorization code requests on its own
  and this cannot be disabled, so Microsoft does return a refresh token. It is
  never persisted, never sent to the browser, and the MSAL token cache is purged
  inside the same request — including when redemption fails.

**Session**
- Stateless AES-256-GCM sealed cookies, keys derived from
  `PORTAL_SESSION_SECRET` via HKDF-SHA256, with separate keys for the session
  and the in-flight authorization transaction.
- Bounded 30-minute lifetime, enforced from **inside** the sealed payload rather
  than from a client-controlled cookie `Max-Age`.
- Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` on any https origin
  (`Secure` is dropped only for `http://localhost` development).
- The session carries display claims only: display name, UPN, tenant ID, object
  ID, authentication timestamp, and a CSRF token.
- **No access token, ID token, or refresh token is placed in a cookie, in the
  page, or in any client-side storage.** The portal ships zero client-side
  JavaScript, so `localStorage`/`sessionStorage` are never touched.
- No server-side session store, so Cloud Run restarts and scale-out never
  invalidate a legitimate session — and there is no unbounded in-memory store to
  exhaust.

**Request hardening**
- CSRF protection on both POST actions via a session-bound token compared in
  constant time.
- `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'
  data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`.
- `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cross-Origin-Opener-Policy`, HSTS on https, `x-powered-by` off.
- All rendered values are HTML-escaped; provider error codes are additionally
  restricted to `[A-Za-z0-9_.:-]{1,64}` before display.

**Secrets and logging**
- No credential is in this repository, in the image, or in any deploy script.
- Secrets arrive only from the environment; in Cloud Run they come from Google
  Secret Manager.
- Logging is one structured line per request containing method, **path**,
  status, and duration. The query string is never logged, so authorization codes
  cannot reach Cloud Logging. MSAL's own logger is silenced and PII logging is
  disabled.
- Startup configuration errors name the missing variable, never a value.

**Authorization boundary**
- Portal sign-in grants access to the portal *only*. It is never an
  authorization signal for ServiceDesk AI. The two systems share an identity
  provider and remain independently authorized; ServiceDesk AI keeps its own
  identity verification, policy gate, and explicit confirmation step.

---

## 6. Configuration

All configuration comes from the environment. Nothing is read from disk.

| Variable | Secret | Example / meaning |
|---|---|---|
| `ENTRA_PORTAL_TENANT_ID` | no | tenant GUID; `common`/`organizations`/`consumers` rejected |
| `ENTRA_PORTAL_CLIENT_ID` | no | application (client) ID of the portal app registration |
| `ENTRA_PORTAL_CLIENT_SECRET` | **yes** | client secret value, from Secret Manager |
| `PORTAL_BASE_URL` | no | public origin, no trailing slash |
| `PORTAL_SESSION_SECRET` | **yes** | ≥32 chars, `openssl rand -base64 48` |
| `PORT` | no | supplied by Cloud Run; defaults to `8080` |

Derived automatically:

- Authority: `https://login.microsoftonline.com/<ENTRA_PORTAL_TENANT_ID>`
- Redirect URI: `<PORTAL_BASE_URL>/auth/redirect`

### Google Secret Manager secret names

```
servicedesk-entra-portal-client-secret
servicedesk-entra-portal-session-secret
```

Create the containers and the least-privilege runtime identity:

```bash
export PROJECT_ID=<your-project>
./scripts/deploy_cloud_run.sh bootstrap-secrets
```

Then add the values by hand (never through a script, never into Git):

```bash
printf '%s' 'PASTE_CLIENT_SECRET_VALUE' \
  | gcloud secrets versions add servicedesk-entra-portal-client-secret \
      --data-file=- --project "$PROJECT_ID"

openssl rand -base64 48 \
  | gcloud secrets versions add servicedesk-entra-portal-session-secret \
      --data-file=- --project "$PROJECT_ID"
```

The Cloud Run runtime service account (`servicedesk-portal-run`) receives
`roles/secretmanager.secretAccessor` on **only these two secrets** and holds no
Microsoft Graph privilege and no other GCP role.

---

## 7. Deployment (two-phase, because of the redirect URI)

Microsoft Entra needs the final Cloud Run hostname in its redirect URI, and that
hostname does not exist until the service is deployed. The URL is never guessed.

### Phase A — deploy and discover the URL

```bash
export PROJECT_ID=<your-project>
export ENTRA_PORTAL_TENANT_ID=<tenant-guid>
export ENTRA_PORTAL_CLIENT_ID=<client-guid>

./scripts/deploy_cloud_run.sh phase-a
```

This deploys the service, reads the real URL, redeploys with
`PORTAL_BASE_URL` set to it, verifies health, and then **stops** and prints the
exact redirect URI to register.

> Cloud Run serves the service on more than one hostname, and `status.url` can
> report the legacy `<service>-<hash>-<region>.a.run.app` form while the deploy
> reports the canonical `<service>-<project-number>.<region>.run.app` form. The
> redirect URI must be pinned to exactly one, so the script treats the URL
> printed by `gcloud run deploy` as authoritative.

**Human action required.** In the Entra admin center → the portal app
registration → *Authentication* → add a **Web** platform with exactly:

```
https://<actual-cloud-run-host>/auth/redirect
```

Leave the implicit-grant checkboxes (*Access tokens*, *ID tokens*) **unchecked**
— this application uses the authorization code flow.

### Phase B — final revision

After the redirect URI is saved:

```bash
./scripts/deploy_cloud_run.sh phase-b
```

### The underlying command

```bash
gcloud run deploy servicedesk-employee-access \
  --source . \
  --project "$PROJECT_ID" \
  --region us-central1 \
  --platform managed \
  --service-account servicedesk-portal-run@"$PROJECT_ID".iam.gserviceaccount.com \
  --port 8080 --cpu 1 --memory 512Mi \
  --min-instances 0 --max-instances 4 --timeout 60s \
  --allow-unauthenticated \
  --set-env-vars "ENTRA_PORTAL_TENANT_ID=$ENTRA_PORTAL_TENANT_ID,ENTRA_PORTAL_CLIENT_ID=$ENTRA_PORTAL_CLIENT_ID,PORTAL_BASE_URL=$PORTAL_BASE_URL" \
  --set-secrets "ENTRA_PORTAL_CLIENT_SECRET=servicedesk-entra-portal-client-secret:latest,PORTAL_SESSION_SECRET=servicedesk-entra-portal-session-secret:latest"
```

`--allow-unauthenticated` is required and intentional: it makes the service
reachable at the transport layer so Microsoft can redirect the browser to it.
Application access is still gated by Microsoft Entra.

---

## 8. Local development

```bash
cd employee_access_portal
npm install
cp .env.example .env      # then fill in real values; .env is git-ignored
npm start
```

Register `http://localhost:8080/auth/redirect` as an additional Web redirect URI
on the app registration for local work. `Secure` is automatically dropped from
cookies on `http://localhost` so sign-in works without TLS.

```bash
npm test          # 61 tests, Node.js built-in runner
npm audit         # 0 vulnerabilities

docker build -t employee-access-portal:test .
docker run --rm -p 8099:8080 --env-file .env employee-access-portal:test
curl http://127.0.0.1:8099/healthz
```

---

## 9. Demo storyboard

| Step | Where | What happens |
|---|---|---|
| **A** | Portal | Account is enabled. Employee signs in with Microsoft. Workspace appears with *Identity Verified* and *Corporate Access Active*. |
| **B** | Entra admin | Operator disables the test employee in Microsoft Entra. |
| **C** | Portal | Employee presses **Verify Corporate Access**. A fresh `prompt=login` authentication is forced and Entra refuses. The workspace becomes unreachable. |
| **D** | ServiceDesk AI | Employee reports: *"I can't access my corporate account."* |
| **E** | ServiceDesk AI | The existing Account Access flow diagnoses **`accountEnabled=false`** from live Microsoft Graph. |
| **F** | ServiceDesk AI | The bot offers governed account enablement. |
| **G** | ServiceDesk AI | The user explicitly confirms. |
| **H** | ServiceDesk AI | The existing Graph backend sets `accountEnabled=true` and verifies the persisted value. |
| **I** | Portal | Employee returns to the Employee Portal. |
| **J** | Portal | Employee presses **Verify Corporate Access** again. |
| **K** | Entra | The fresh authentication now succeeds. |
| **L** | Portal | The workspace displays *Identity Verified* and *Corporate Access Active* for the same UPN. |

Nothing in steps C, K, or L is simulated by this portal. Every one of them is
Microsoft Entra deciding.

### Terminology

This is the **Microsoft Entra disabled account / account enablement** use case.

It is **not** an AD DS lockout demonstration. Microsoft Graph exposes
`accountEnabled` as authoritative for enable/disable state, but it does **not**
expose a current AD DS lockout boolean on the user resource — which is exactly
what the existing ServiceDesk implementation already documents and honours.
Classic AD DS unlock is a separate future use case requiring an AD DS connector.

---

## 10. Tests

`npm test` — **61 tests, all passing.** Every required behaviour is covered:

| Required behaviour | Test file |
|---|---|
| `/healthz` returns 200 without authentication | `health.test.js` |
| unauthenticated `/workspace` redirects to sign-in | `workspace.test.js` |
| authenticated workspace rendering | `workspace.test.js` |
| callback rejects invalid state | `auth-callback.test.js` |
| callback rejects missing code | `auth-callback.test.js` |
| Verify Corporate Access clears the local session | `verify-access.test.js` |
| Verify Corporate Access uses `prompt=login` | `verify-access.test.js` |
| protected route does not trust client-supplied identity | `workspace.test.js` |
| no administrative Graph scopes requested | `security-posture.test.js`, `entra-client.test.js` |
| no Graph mutation endpoints exist in the portal | `security-posture.test.js` |
| cookies are Secure/HttpOnly appropriately in production | `security-posture.test.js` |
| secret values are not logged | `security-posture.test.js` |

`entra-client.test.js` exercises the **real** `src/entra.js` by substituting
`@azure/msal-node` in the CommonJS module cache, so scope selection, PKCE,
response mode, `prompt` handling, nonce validation, tenant validation, and token
cache purging are all asserted against production code.

`security-posture.test.js` additionally performs static assertions over the
shipped source so that a future change which starts administering accounts from
the portal fails the build: no `graph.microsoft.com`, no `accountEnabled`, no
`passwordProfile`, no `.default` scope, no outbound HTTP client, no host other
than Microsoft, and no ServiceDesk AI configuration.

### Acceptance testing

The injected Entra client in the unit tests is a development convenience and is
**explicitly not accepted as end-to-end evidence**. E2E acceptance (Tests A–E of
the use case) requires live Microsoft Entra authentication against the real
tenant, with a real employee account being disabled and re-enabled through the
existing ServiceDesk AI Graph flow.

---

## 11. Relationship to the existing ServiceDesk AI backend

Inspected read-only; **nothing in it was modified**:

- `sd_chat/tools/aad_tool.py` — Graph client-credentials token acquisition,
  `_graph_get` / `_graph_patch`.
- `sd_chat/tools/ad_account_tool.py` — `AD_ACCOUNT_MODE=graph`, reads the
  authoritative boolean `accountEnabled`, and `ad_enable_account` →
  `_enable_graph_account` which PATCHes `{"accountEnabled": true}` and then
  re-reads Graph for up to 60s to verify the persisted value before claiming
  success.
- `sd_chat/tools/account_access_orchestrator.py` — identity verification,
  diagnosis, offer, and `confirm_account_access_offer` confirmation gate.
- `sd_chat/tools/policy_tool.py` — `consume_account_access_authorization`.

That backend already supports everything the demonstration needs. The portal
adds no capability to it, weakens no authorization, and bypasses neither
identity verification nor the existing confirmation step.
