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
