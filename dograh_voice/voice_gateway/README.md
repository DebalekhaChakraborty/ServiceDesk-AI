# Voice Gateway — Dograh → existing ServiceDesk (`sd_chat`)

A deliberately narrow adapter. It forwards one caller utterance to the
**already-running** `sd_chat` agent over its standard ADK REST API and returns
the reply verbatim.

It holds no conversation state, makes no decisions, has no privileged tools, and
**nothing under `sd_chat/` was modified** to make it work.

```
laptop mic → Dograh STT → servicedesk_voice_turn tool
                              ↓  http://172.18.0.1:8010/voice/turn
                          voice_gateway
                              ↓  POST /run   (standard ADK API)
                          sd_chat  :8000     ← unchanged, not restarted
                              ↑
                          voice_gateway → Dograh TTS → speaker
```

---

## The three journeys, and which one is canonical

### PRIMARY — external caller with any Service Desk need (the product)

This is what ServiceDesk Voice AI is *for*. The caller **cannot sign in to
Entra**, so nothing about them is trusted when the call starts — and that is all
it tells us. They may want a locked account, a forgotten password, VPN, a
printer, software, an incident, a request, or anything else the Service Desk
handles. **The line is not an account-recovery bot.** Duo is how it proves who
they are, not what it is for.

```
external caller (no corporate identity)
  → public entry               ← employee-facing, no login
  → server-minted RECOVERY bootstrap   (purpose=account_recovery, NO identity)
  → Dograh workflow → servicedesk_voice_turn → voice_gateway
  → "Welcome to ServiceDesk. How can I help you today?"
  → caller states the problem            ← HELD server-side, forwarded to nothing
  → caller speaks an employee ID / UPN / mobile   ← selects a CANDIDATE only
  → Duo preauth → available factor → human verification
  → Graph corroboration against the MAPPED Entra object id
  → trusted identity_context (duo_recovery / self_account_recovery)
  → the ORIGINAL request is released to sd_chat, exactly once
```

The spoken identifier **selects a candidate row and nothing more**. Duo decides
who the human is; the identity that leaves the gateway is read back from the row
bound to `duo_user_id`, never from what was said.

The stated problem is held in `pending_request` for the whole of that journey.
It is a problem statement and carries no authority: it selects no account,
bypasses no factor, is never placed in the signed bootstrap, is never a preset
parameter, and cannot itself cause a forward. Every failure — bad identifier,
Duo deny, Duo timeout, Graph contradiction, Graph outage, no usable factor,
session expiry — leaves it exactly where it is. It reaches sd_chat only from
inside `_verified`, past both gates, and the one-shot flag means it reaches it
once.

`purpose=account_recovery` is retained as the bootstrap's **token identity**, not
a claim about the caller's intent. It is an identity-free external-call
bootstrap; renaming it would break token compatibility for no functional gain.

### SECONDARY — authenticated portal voice (optional shortcut)

A convenience for someone who *can* already sign in and would rather talk than
type. It is **not** the recovery architecture.

```
authenticated portal session → POST /voice/session
  → server-minted AUTHENTICATED token (call-bound, signed Entra identity)
  → same workflow, same tool, same gateway
  → no Duo recovery challenge (identity is already trusted)
  → sd_chat
```

### DEVELOPER — external-recovery test bootstrap

Behaves exactly like an external caller. See
`provisioning/recovery_test_bootstrap.py`; off unless
`VOICE_DOGRAH_RECOVERY_TEST_MODE=true`.

> **The Dograh admin console is NOT the employee-facing channel.** It is an
> admin/developer surface for workflow, model and tool configuration, and it
> stays private. The public employee entry point is `/recovery` (later:
> phone/SIP). A console **Test Call** carries no `initial_context`, so both
> required presets render empty and the call is refused — that is the boundary
> working, not a defect.

### The only two accepted bootstraps

| | RECOVERY | AUTHENTICATED |
|---|---|---|
| claims | `ver, call_id, purpose, iat, exp, aud` | `ver, call_id, upn, iat, exp, aud` (+`name`,`oid`) |
| asserts identity | **no** | yes, signed |
| minted by | `/recovery/start` (public) | `/voice/session` (session required) |
| identity comes from | Duo + the local map, later | the sealed portal session |

Anything else — missing, malformed, wrong audience, wrong purpose, expired,
wrong `call_id` — **fails closed**. "No token" never means anonymous recovery;
that would bypass Duo and Graph entirely.

---

> ## ⚠️ POC SINGLE SESSION MODE — NOT SAFE FOR MULTI-CALLER USE
>
> When `VOICE_GATEWAY_POC_SINGLE_SESSION=true`, **every request shares one
> ServiceDesk conversation** (`dograh-poc-voice`). This exists only because
> Dograh v1.45.0 cannot supply a per-call identifier (see below), and it is
> valid **only** while:
>
> - exactly **one human tester** is using it;
> - the conversation is **harmless and non-mutating**;
> - **concurrent callers are unsupported** — a second overlapping turn is
>   refused with `409 CONCURRENT_TURN_REJECTED` rather than being spliced into
>   someone else's conversation.
>
> **This mode must never be used for Account Access, account enable/disable,
> password reset, ServiceNow mutation, Windows remediation, or any other
> privileged operation.**
>
> Enforcement of that restriction lives in ServiceDesk, not here — see
> *Why there is no keyword filter* below.

---

## Discovered ServiceDesk contract

`sd_chat/server_with_upload.py` is built on
`google.adk.cli.fast_api.get_fast_api_app`, so it already exposes the **standard
ADK REST API** — no custom endpoint was needed and none was added.

Verified read-only against the live server's `/openapi.json`:

| Endpoint | Use |
|---|---|
| `POST /apps/{app}/users/{user}/sessions/{session_id}` | create a session **with our own id** |
| `GET /apps/{app}/users/{user}/sessions/{session_id}` | existence check |
| `POST /run` | one non-streaming turn |
| `GET /health` | liveness |

`POST /run` body (`RunAgentRequest`): `appName`, `userId`, `sessionId` required;
`newMessage` = `{"role":"user","parts":[{"text":...}]}`; `streaming: false`.
It returns a list of events. The reply is the **last** event with
`content.role == "model"` and non-empty text — note a tool-result event carries
`role: "user"`, so filtering on role alone is not sufficient.

`app_name` is **`sd_chat`** (from `/list-apps`).

## Session continuity

`voice_session_id` maps deterministically to a ServiceDesk session id:

```
voice-{sanitised-first-48-chars}-{sha256(original)[:8]}
```

Same call id → same ServiceDesk session, so turn 2 ("Yes.") lands in the same
conversation as turn 1. The digest of the *original* value is appended so two
call ids that normalise identically can never collide. There is no second
conversation-state engine: ADK remains the single source of truth, and the
in-process registry is only an optimisation to skip a redundant existence check.

In PoC single-session mode the id is **resolved server-side** and any value in
the request body is ignored, so the LLM cannot influence session routing.

## Identity — no assertion is made

`resolve_identity_context` returns `{"ok": false, "source": "none"}` for gateway
traffic, exactly as it does for an unauthenticated web caller, and ServiceDesk
still answers harmless questions. That behaviour is preserved deliberately:

- sessions are created with **empty state** — seeding a persona would silently
  change `identity_context_tool`;
- `userId` is the constant `voice-channel`, a **channel namespace, not an
  identity**;
- a `verified_upn` supplied in the request is **dropped and logged as ignored**.

### Why there is no keyword filter on privileged requests

A denylist here would be worse than useless. It would give false assurance while
being trivially bypassed by paraphrase, and it would misfire on legitimate
speech — *"I cannot access my account"* is a perfectly ordinary opening
utterance that a naive filter would block.

The real control already exists and is untouched: **ServiceDesk owns policy,
confirmation, and identity gating**, and it currently sees an unverified caller
(`ok: false`). Privileged operations remain gated by `sd_chat`'s own unchanged
identity controls. Duplicating that logic in the gateway would violate the
architectural rule that Dograh and the gateway are transport only.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | `{"status":"ok","servicedesk":"…","poc_single_session":bool}` |
| `POST` | `/voice/turn` | the only functional route |

Nothing else exists — `/docs`, `/redoc` and `/openapi.json` are disabled.

```jsonc
// request — PoC mode: text only, no session id
{"text": "Hello, what can you help me with?"}
// request — normal mode
{"voice_session_id": "dograh-call-abc123", "text": "Hello…"}
// response
{"voice_session_id": "dograh-poc-voice", "text": "<exact ServiceDesk reply>", "status": "ok"}
// error — structured, no stack traces, no internals
{"status": "error", "code": "SERVICEDESK_UNAVAILABLE", "text": "The Service Desk service is temporarily unavailable."}
```

Error codes: `EMPTY_UTTERANCE`, `UTTERANCE_TOO_LONG` (400);
`MISSING_VOICE_SESSION_ID` (422); `CONCURRENT_TURN_REJECTED` (409);
`SERVICEDESK_UNAVAILABLE`, `SERVICEDESK_TIMEOUT`, `SERVICEDESK_BAD_STATUS`,
`SERVICEDESK_MALFORMED_RESPONSE`, `GATEWAY_ERROR` (502).

## Running

```bash
cd /home/AI_POC/servicedesk-ai/dograh_voice
VOICE_GATEWAY_HOST=172.18.0.1 \
VOICE_GATEWAY_POC_SINGLE_SESSION=true \
/home/AI_POC/venvs/debalekha/bin/python -m voice_gateway.app
```

`main()` **refuses to start** on a non-private bind, so `0.0.0.0` and any
globally-routable address are impossible by construction. The check uses real
address classification (`ipaddress`), not string prefixes — `172.` alone is not
a private marker, since `172.32.0.0/12` upward is public.

| Env var | Default | Notes |
|---|---|---|
| `VOICE_GATEWAY_HOST` | `127.0.0.1` | set to `172.18.0.1` for container access |
| `VOICE_GATEWAY_PORT` | `8010` | |
| `SERVICEDESK_BASE_URL` | `http://127.0.0.1:8000` | |
| `SERVICEDESK_APP_NAME` | `sd_chat` | |
| `SERVICEDESK_USER_ID` | `voice-channel` | channel namespace, not an identity |
| `SERVICEDESK_TIMEOUT_SECONDS` | `120` | |
| `VOICE_GATEWAY_MAX_TEXT_CHARS` | `4000` | |
| `VOICE_GATEWAY_LOG_UTTERANCES` | `false` | |
| `VOICE_GATEWAY_POC_SINGLE_SESSION` | `false` | see warning above |
| `VOICE_GATEWAY_POC_SESSION_ID` | `dograh-poc-voice` | |

## Reachability — verified, not assumed

`dograh_voice_app-network` is `172.18.0.0/16`, **gateway `172.18.0.1`**, carried
on host interface `br-77fe4ae303c2`. A process bound only to `127.0.0.1` is
**not** reachable through that bridge address — so the gateway binds the bridge
address directly.

Proven not publicly exposed:

| Check | Result |
|---|---|
| listener | `172.18.0.1:8010` only — no wildcard bind |
| from `dograh_voice-api-1` | `GET http://172.18.0.1:8010/health` → **200** |
| from the VPC NIC `10.128.0.2:8010` | connection refused |
| from `dograh-turn` (separate VPC, public IP `34.44.75.208`) | both `10.128.0.2:8010` and `172.18.0.1:8010` unreachable |
| GCP firewall rules mentioning 8010 | **0** |
| `dev-linux-instance` external IP | **none** |

ServiceDesk `:8000` gained no new exposure; Postgres and Redis stay internal;
Dograh UI/API exposure, TURN, IAP and firewall are all untouched.

## Logging

Emitted: timestamp, 12-char hashed session handle, duration, status, error code,
reply length. **Never** emitted: raw `voice_session_id`, caller utterances (unless
`VOICE_GATEWAY_LOG_UTTERANCES=true`), tokens, credentials, stack traces.

## Tests

```bash
cd /home/AI_POC/servicedesk-ai/dograh_voice
/home/AI_POC/venvs/debalekha/bin/python -m pytest voice_gateway/tests/ -q
```

**31 tests**, downstream faked with `httpx.MockTransport`. No ServiceDesk test
was modified.

---

# Phase 4 — Dograh tool configuration (NOT yet applied)

## Why PoC single-session mode is required — settled from source

Rather than infer this from a single live observation, the shipped v1.45.0 image
was read directly (`/app/api/services/workflow/tools/custom_tool.py`,
`pipecat_engine_custom_tools.py`):

1. **Headers are never templated.** `headers = dict(config.get("headers", {}) or {})`
   is passed straight to the request with no `render_template` call. A header of
   `X-Dograh-Run: {{workflow_run_id}}` would arrive **literally**, as that exact
   string.
2. **`workflow_run_id` is not in the tool render context.** That context is built
   only from `initial_context` + `gathered_context`
   (`{**initial_context, **gathered_context, "initial_context": …, "gathered_context": …}`).
   `_workflow_run_id` exists on the engine but is used solely for logging and
   persistence — it is never exposed to a tool's URL, headers, body, or
   parameters.

So there is **no supported way for Dograh v1.45.0 to hand the gateway a
per-call id**, and no further undocumented template tricks were attempted. The
session id is therefore resolved server-side in the gateway.

**Useful finding for later:** custom tools support *preset parameters* with a
`value_template` rendered **server-side** (`_resolve_preset_parameters`), so a
parameter can be filled without LLM involvement — but only from
`initial_context`/`gathered_context`. Once Phase 7 triggers calls via API, a call
id passed in `initial_context` plus a preset parameter
`value_template: "{{call_id}}"` becomes the correct **per-call, non-LLM**
solution, and PoC single-session mode can be retired.

## Exact manual steps in the Dograh UI

1. Open `http://localhost:3010` through the IAP/SSH forward.
2. **Tools → New Tool → HTTP API.**

| Field | Value |
|---|---|
| **Tool Name** | `servicedesk_voice_turn` |
| **Method** | `POST` |
| **URL** | `http://172.18.0.1:8010/voice/turn` *(include `http://` — a missing protocol is the documented common mistake)* |
| **Headers** | `Content-Type: application/json` |
| **Authentication** | none |

**Tool Description** (this is how the LLM decides when to call it):

> Send the caller's exact words to the Service Desk and get the official reply.
> Call this for EVERY caller utterance without exception. The Service Desk is the
> only authority on IT questions, troubleshooting, account access, and incidents.
> Never answer from your own knowledge.

**Parameters** — exactly one:

| Name | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes | The caller's current utterance, transcribed **verbatim**. Do not summarise, correct, translate, or rephrase it. Send only what the caller just said. |

**Do not add a `voice_session_id` parameter.** The gateway assigns the session
itself; an LLM-supplied value would be ignored anyway, and asking for one invites
the model to invent identifiers.

3. **Attach the tool** to the Agent node that handles the conversation.

## Exact Agent-node prompt

```
You are the voice channel for the Service Desk. You are ears and mouth only —
you do not reason about IT problems yourself.

For EVERY utterance the caller makes, call the tool `servicedesk_voice_turn`,
passing the caller's current words verbatim as `text`.

The tool returns the Service Desk's official response. Treat that returned text
as authoritative and final:
  - Speak it back faithfully and completely.
  - Do not summarise it, shorten it, embellish it, or reinterpret it.
  - Do not add remediation steps, advice, or troubleshooting of your own.
  - Do not answer any Service Desk question from your own knowledge, even if you
    are confident you know the answer.

You have no infrastructure tools of your own and must never attempt account
changes, password resets, or ticket operations directly.

If the tool returns an error message, read that message to the caller as-is and
wait for their reply.
```

## Acceptance test (requires a human at the laptop)

1. Dograh container → gateway `/health` = 200 ✔ *(already proven)*
2. Start one Dograh Test Audio call.
3. Say: *"Hello, what can you help me with?"*
4. STT → `servicedesk_voice_turn` → existing `sd_chat`.
5. The reply returns through the gateway.
6. Dograh speaks it.
7. In the **same call**, ask: *"What was the first thing I asked you?"*
8. ServiceDesk must demonstrate continuity.
9. End call.

No mutation use cases. Verify afterwards:

```bash
curl -s http://127.0.0.1:8000/apps/sd_chat/users/voice-channel/sessions
# gateway log: one line per turn, hashed handle only
```

## Explicitly still out of scope

Caller identity verification, TOTP/OTP, account enable/disable, password reset,
Graph or ServiceNow mutation, telephony, public exposure, TURN/IAP/firewall
changes, and any change to `sd_chat/`.

## Duo recovery (Phase 7)

Cisco Duo **Auth API** is the active recovery MFA provider. The Admin API is not
used and must not be: it is unavailable on Duo Free and carries directory-wide
write authority this flow has no need for.

### The external conversation (Phase 7.6 — ServiceDesk-first)

The line asks what the caller needs **before** it asks who they are.

```
AWAITING_REQUEST          ← every external call starts here
  ├─ greeting / noise            → stay, answer naturally      ("hello" sends NO push)
  ├─ identifier only             → stay, retain candidate, ask what they need
  └─ a Service Desk request      → capture verbatim, → AWAITING_IDENTIFIER
AWAITING_IDENTIFIER       → AWAITING_FACTOR_CHOICE | AWAITING_PASSCODE
AWAITING_FACTOR_CHOICE    → PUSH_PENDING | AWAITING_PASSCODE
PUSH_PENDING/AWAITING_PASSCODE
                          → VERIFIED           (no request was ever stated)
                          → SERVICEDESK_ACTIVE (carrying the original request)
                          → FAILED_LOCKED | FAILED_UNAVAILABLE
```

Before 7.6 the call opened in `AWAITING_IDENTIFIER` and the first thing a caller
heard was *"tell me your employee ID"*. That framed a general Service Desk line
as an account-recovery bot, and made a caller with a VPN problem answer a
question about identity they had no reason to expect.

Three deterministic rules replace it, in `conversation.py`. **No LLM is
involved**, because every one of these decisions sits on the path to a trust
transition:

| The caller says | What it is | What happens |
|---|---|---|
| "hello", "can you hear me" | a greeting | answered; no capture, no Duo, no budget spent |
| "my employee ID is 1999" | identifier material | retained as an untrusted candidate; asked what they need |
| "my VPN keeps disconnecting" | a request | captured verbatim; verification begins |
| "my VPN is down, ID 1999" | both | request captured **and** candidate resolved in one turn |

The retained identifier is a convenience, not a shortcut: it goes through the
same `_resolve_identifier` path as a spoken one, attempt budget included.

#### The pending request

`pending_request` holds the caller's exact words for the whole authentication
journey. What it is **not**:

- not an identity — it selects no account and proves nothing;
- not in the signed bootstrap, and not a preset parameter;
- not settable from the browser, and not overridable by a later utterance;
- not able to override `call_id` or `voice_identity_token`;
- not logged (only its shape is), and not in `public_state()`.

It is released in exactly one place — inside `_verified`, past both the Duo
`allow` and the live Graph corroboration — and a one-shot flag means once.
Every failure path leaves it untouched: bad identifier, Duo deny, Duo timeout,
Graph contradiction, Graph outage, no usable factor, session expiry. On release
the gateway speaks `VERIFIED_CONTINUING` followed by the real sd_chat reply, so
the caller states the problem once.

#### Naming

`/recovery/start` and `purpose=account_recovery` are unchanged. Treat them as an
**identity-free external-call bootstrap**, not an assertion that the caller wants
their account back. Renaming them would break token compatibility for no
functional gain.

### Configuration

Environment first, then a 0600 file in `dograh_voice/runtime/`. Never argv.

| Setting | Env | File | Secret? |
|---|---|---|---|
| Integration key | `DUO_IKEY` | `.duo_ikey` | no |
| Secret key | `DUO_SKEY` | `.duo_skey` | **yes** |
| API hostname | `DUO_HOST` | `.duo_host` | no |
| Signature algorithm | `DUO_SIGNATURE_ALGORITHM` | — | no (default `sha512`) |
| Provider selection | `RECOVERY_PROVIDER` | — | no (default `duo`) |
| Identity map path | `RECOVERY_IDENTITY_DB` | — | no |
| Default calling code | `RECOVERY_DEFAULT_CALLING_CODE` | — | no |

`DUO_HOST` must match `api-XXXXXXXX.duosecurity.com` (or `.duofederal.com`).
Anything else is refused at construction, so no caller- or model-supplied
hostname can ever be signed with our integration key.

`GET /auth/v2/check` runs at startup. If it fails, recovery is **disabled** —
a half-working MFA path looks like a recovery route and is not one.

**Required** read-only Graph corroboration:
`RECOVERY_GRAPH_TENANT_ID`, `RECOVERY_GRAPH_CLIENT_ID`, and
`RECOVERY_GRAPH_CLIENT_SECRET` — each resolvable from env **or** a 0600 runtime
file. Unset means recovery is **disabled** at startup, for the same reason a
failed `/auth/v2/check` disables it: without corroboration no call could ever
succeed.

### Starting the gateway

One command, from `dograh_voice/`, with the project venv active:

```bash
python -m voice_gateway.app
```

That is the whole mechanism. **Do not export configuration into the shell and
do not add a wrapper script.** Every value resolves environment-first, then
from an owner-only file in `dograh_voice/runtime/` — so a start that forgets an
export cannot silently come up with corroboration disabled, which (since
corroboration is mandatory) would silently mean no recovery at all.

| Runtime file (all 0600, all git-ignored) | Supplies |
|---|---|
| `.duo_ikey` / `.duo_skey` / `.duo_host` | Duo Auth API credentials |
| `.recovery_graph_tenant_id` | `RECOVERY_GRAPH_TENANT_ID` |
| `.recovery_graph_client_id` | `RECOVERY_GRAPH_CLIENT_ID` |
| `.recovery_graph_client_secret` | `RECOVERY_GRAPH_CLIENT_SECRET` |
| `.recovery_default_calling_code` | `RECOVERY_DEFAULT_CALLING_CODE` |
| `.voice_identity_secret` | portal token signing key |
| `.recovery_store_key` | enrollment admin key material |
| `recovery_identity.db` | the employee identity map |

A file that is not owner-only is **ignored and logged by name** rather than
read, so a `chmod` slip shows up as a specific warning instead of an
unexplained `recovery DISABLED`.

Bind address, port and all ServiceDesk connection settings keep their existing
defaults (`127.0.0.1:8010` → `http://127.0.0.1:8000`) and are still overridable
by environment for a non-default deployment.

The calling code is **never defaulted in code**: a guessed country would make a
caller's spoken mobile number silently match nobody.

#### Corroboration fails closed

A Duo `allow` proves possession of the enrolled phone. It does not establish an
identity on its own — the local map row it would be read from could be stale.
Before any recovery persona is built, Graph must confirm, live, that the mapped
object id still exists in the expected tenant.

| Graph outcome | Result | Caller hears |
|---|---|---|
| object confirmed in tenant | persona built | verified |
| object missing | `FAILED_LOCKED` | locked (terminal) |
| wrong tenant | `FAILED_LOCKED` | locked (terminal) |
| Graph down / 5xx / not configured | `FAILED_UNAVAILABLE` | try again shortly |

An outage is terminal for the call but charges the account **no** failure, so a
Graph incident cannot lock every employee out of recovery.

UPN drift stays informational: the directory's new UPN is surfaced as
`upn_drift_detected` and never retargets the call. The mapped Entra object id
remains authoritative throughout.

#### Activation-code lifetime

`duo_activation_code` is temporary enrollment material and the only
secret-like value the identity map holds. It exists while `enroll_status` is
`waiting` and is destroyed the moment enrollment reaches a terminal state —
`NULL` on `success` (via `activate_duo`) and `NULL` on `invalid`/expired (via
`invalidate_duo_enrollment`). `duo_user_id` is the permanent Duo binding and
survives both.

### Identity map

`dograh_voice/runtime/recovery_identity.db` — SQLite, mode 0600, git-ignored,
schema v1. Provisioned from a shell on the host only:

```
python -m voice_gateway.identity_map_admin upsert \
    --employee-id 1798283 --tenant <guid> --object-id <oid> \
    --upn person@example.com --mobile +14155550123 --display-name "Name"
```

Canonical corporate identity is `entra_tenant_id + entra_object_id`; the
canonical Duo binding is `duo_user_id`. `employee_id`, `upn` and `mobile_e164`
are **lookup aliases only** and authenticate nobody.

### Known limitation, unchanged from Phase 6

Dograh v1.45.0 builds `AudioBufferProcessor` and registers the audio data
handler unconditionally, and `transcript_configuration` exposes only
`include_end_timestamps`. **A spoken Duo passcode therefore appears in the call
recording and transcript, and no supported setting disables that.** Duo Push
avoids the issue entirely and is the preferred factor for this reason.
