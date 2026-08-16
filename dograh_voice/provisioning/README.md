# Dograh config-as-code + Vertex BYOC

Provisions the ServiceDesk voice agent through Dograh's **official REST API**.
No direct PostgreSQL writes, no upstream source changes, no browser automation.

> ## ✅ APPLIED — both original blockers are cleared
>
> 1. **Dograh API key** — a human created `servicedesk-provisioning`; it lives in
>    `runtime/.dograh_api_key` (0600, git-ignored).
> 2. **Vertex auth** — solved **without touching the VM**. The earlier diagnosis
>    (widen GCE access scopes, requiring an instance stop) was wrong for this
>    host: no Gemini workload here uses the metadata credential. sd_chat and
>    every other ADK agent authenticate through the operator's gcloud **user
>    ADC**, so Dograh now does the same via a read-only mount. See
>    "ADC without a VM restart" below.
>
> Still outstanding: the **human audio acceptance call** (Gate 5).

## Files

| File | Purpose |
|---|---|
| `dograh_client.py` | REST client; `X-API-Key` auth from env or git-ignored file; `redact()` for all output |
| `desired_state.py` | Declarative tool + model config; `find_dograh_providers()` fallback detector |
| `configure_tool.py` | Idempotent create/update of `servicedesk_voice_turn` |
| `configure_agent.py` | Surgical workflow patch — attaches tool + prompt to the agent node |
| `configure_models.py` | Switches inference to Vertex/ADC; **fails closed** on Dograh fallback |
| `verify.py` | Read-only assertion of the provisioned state |

Every mutating script takes `--dry-run`.

```bash
cd /home/AI_POC/servicedesk-ai/dograh_voice
PY=/home/AI_POC/venvs/debalekha/bin/python
$PY -m provisioning.configure_tool   --dry-run
$PY -m provisioning.configure_agent  --tool-uuid <uuid> --name-hint "ServiceDesk" --dry-run
$PY -m provisioning.configure_models --dry-run
$PY -m provisioning.verify
```

## Endpoints used

`GET/POST /api/v1/tools/` · `GET/PUT /api/v1/tools/{tool_uuid}` ·
`GET /api/v1/workflow/fetch` · `GET /api/v1/workflow/fetch/{id}` ·
`PUT /api/v1/workflow/{id}` · `POST /api/v1/workflow/{id}/validate` ·
`GET /api/v1/user/configurations/defaults` ·
`GET/PUT /api/v1/user/configurations/user` ·
`GET /api/v1/user/configurations/user/validate`

Base URL defaults to `http://127.0.0.1:8001` (the loopback-published Dograh API).

## Idempotency

- **Tool** — found by *exact* name. Absent → create. Present → compare `name`,
  `description`, `definition`; update only on real difference. Repeat runs are
  no-ops and never duplicate.
- **Workflow** — definition fetched first, deep-copied, and patched surgically.
  Node count is asserted unchanged; edges, settings, greeting, and every
  unrelated node pass through untouched. Ambiguous workflow or multiple agent
  nodes → **refuse and ask**, never guess.

## Schema notes taken from the live deployment

Read from this deployment's own `/api/v1/openapi.json`, not from memory:

- `HttpApiConfig.timeout_ms` **defaults to 5000**. Real ServiceDesk turns run
  2–6 s and longer with tools, so the desired state sets **120000** explicitly.
  Leaving the default would truncate live calls.
- `GoogleVertexRealtimeLLMConfiguration` — requires `project_id`; model default
  `google/gemini-live-2.5-flash-native-audio`; voice default `Charon`;
  `credentials` and `api_key` optional.
- `GoogleVertexLLMConfiguration` — requires `project_id`; model default
  `gemini-3.5-flash`; `credentials`/`api_key` optional.
- **Omitting `credentials` and `api_key` is what selects ADC.** The scripts
  assert those keys are absent rather than empty.

## No Dograh credit path

`find_dograh_providers()` walks the whole config for `mode`/`provider` values in
`{dograh, dograh_realtime}`. `configure_models.py` re-reads the config after the
PUT and raises `DograhFallbackDetected` if any remain — so a silent fallback to
billed inference cannot survive the script. No Service Key is created and
`services.dograh.com` is never used.

**Current state: `MODEL_CONFIGURATION_V2 = {"version": 2, "mode": "dograh", …}`**
— i.e. inference is billed to Dograh credits today.

## ADC without a VM restart

`google.auth.default()` searches `GOOGLE_APPLICATION_CREDENTIALS` →
`~/.config/gcloud/application_default_credentials.json` → GCE metadata. On this
host the gcloud file exists, so **metadata is never reached** — which is why
sd_chat calls Vertex happily while a raw metadata token gets
`403 insufficient authentication scopes`. Same endpoint, same minute:

| credential | us-central1 | us-east4 |
|---|---|---|
| user ADC | 200 | 200 |
| metadata token | 403 | 403 |

The container runs as uid 999 and the canonical file is 0600 owned by uid 1000,
so it cannot be bind-mounted directly. `runtime/adc/` holds a copy owned by
uid **999**, mode **0400**; host uid 999 is unassigned, so no host account can
read it, and the canonical file keeps mode 0600. The copy is git-ignored and
mounted read-only — never baked into an image, never in source.

Verified inside `dograh_voice-api-1`: credential class
`google.oauth2.credentials.Credentials` (**not** `compute_engine`), and real
Vertex calls succeed.

## Model and location choices — measured, not assumed

Vertex was queried from inside the container:

| model | global | us-central1 | us-east4 |
|---|---|---|---|
| `google/gemini-live-2.5-flash-native-audio` | 1008 not found | **connected, 41.8 KB audio** | connected, 38.0 KB audio |
| `gemini-3.5-flash` | **HTTP 200** | 404 | 404 |

So the two services need **different** locations: realtime on `us-central1`
(this VM is in `us-central1-c`, keeping media in-region), auxiliary LLM on
`global`. Dograh substitutes `us-east4` when `location` is empty
(`service_factory.py`: `location or "us-east4"`), which would 404 the auxiliary
model — both are therefore always sent explicitly, and a test enforces it.

---

## BLOCKER 1 (RESOLVED) — Dograh API key bootstrap

`GET/POST /api/v1/user/api-keys` exist, and auth accepts either an `X-API-Key`
header or an `Authorization: Bearer` local-JWT. A key row already exists:

```
id=1  key_prefix=dgr_fQqQ  is_active=t  created_by=1 (debalekha.chakraborty@tcs.com)
```

It is **hashed at rest**, so the plaintext cannot be recovered. Options:

1. **You already have the key** → write it to
   `dograh_voice/runtime/.dograh_api_key` (mode `0600`, git-ignored) or export
   `DOGRAH_API_KEY`. Nothing else needed.
2. **Create a fresh one in the UI** (recommended if the old value is lost):
   `http://localhost:3010` → Settings → API Keys → create → copy once → store as
   above. One-time human action; everything after is code-driven.
3. **Programmatic** — log in with email/password to obtain a local JWT, then
   `POST /api/v1/user/api-keys`. **Not recommended and not implemented**: it
   would require your Dograh password, which must not enter source or env here.

There is a fourth theoretical route — minting a local JWT with the deployment's
own `OSS_JWT_SECRET` (which we generated at install and hold in
`runtime/.env`). It needs no password and is fully code-driven, but it is an
authentication bypass against your own instance. **Deliberately not done without
explicit approval.** Say so if you want it.

## BLOCKER 2 — Vertex ADC blocked by GCE access scopes

**IAM is not the problem.** The attached service account already holds
`roles/editor` (plus Secret Manager roles) — more than enough for Vertex, and
already broader than least privilege.

**Access scopes are the problem.** The instance's token carries only:

```
devstorage.read_only  logging.write  monitoring.write
service.management.readonly  servicecontrol  trace.append
```

`cloud-platform` is absent. Proven empirically against a real Vertex endpoint:

```
GET .../v1/projects/ai-and-automation-coe/locations/us-central1
  → HTTP 403  PERMISSION_DENIED
     "Request had insufficient authentication scopes."
```

ADC plumbing itself is fine — the metadata server **is** reachable from inside
`dograh_voice-api-1` and returns a token. The token is simply scoped too
narrowly, so Vertex will reject it no matter what IAM says.

### Why this is a hard stop

GCE access scopes are **immutable on a running instance**. Changing them means:

```
gcloud compute instances stop  dev-linux-instance          # ← downtime
gcloud compute instances set-service-account dev-linux-instance \
    --service-account=839673506922-compute@developer.gserviceaccount.com \
    --scopes=https://www.googleapis.com/auth/cloud-platform
gcloud compute instances start dev-linux-instance
```

That stop would terminate **ServiceDesk PID 3396520**, all five Dograh
containers, the voice gateway, and your VS Code sessions — directly against this
phase's "do not restart ServiceDesk" rule. **Not done. Your call.**

### Options

| Option | Downtime | Notes |
|---|---|---|
| **A. Stop/start this VM to widen scopes** | yes, minutes | Simplest. Everything restarts; TURN and firewall untouched. Needs an agreed window. |
| **B. Run Dograh inference from a different VM** created with `cloud-platform` scope | none here | More infrastructure; splits the deployment. |
| **C. Service-account JSON key** mounted into the container | none | **Works around scopes entirely**, but contradicts "no JSON key unless ADC is proven impossible" and puts long-lived credentials on disk. ADC *is* proven impossible **on this instance as currently configured** — so this is now a legitimate option, though still the least preferred. |
| **D. Stay on Dograh credits for now** | none | No progress on the credit objective. |

**Recommendation: A**, during an agreed maintenance window. If downtime is
unacceptable, C is the pragmatic second choice, scoped to a dedicated
least-privilege service account (`roles/aiplatform.user` only — *not* the
`roles/editor` account currently attached).

Least-privilege note for whichever option: prefer granting
`roles/aiplatform.user` to a purpose-made service account rather than relying on
the existing `roles/editor` binding.

### Not attempted

The GCP-only split fallback (Cloud STT + Vertex LLM + Cloud TTS) is **also
blocked by the same scope limitation** — `GoogleSTTConfiguration` and
`GoogleTTSConfiguration` authenticate the same way. Fixing scopes unblocks both
paths, so there is no fallback worth applying first.

## Developer external-recovery bootstrap

`recovery_test_bootstrap.py` starts the **canonical external-recovery journey**
from a shell, for development only.

### Why it exists

Dograh v1.45's native Test/Run button cannot carry trusted context. The live
API is unambiguous:

```
POST /api/v1/workflow/{id}/runs   CreateWorkflowRunRequest = {mode, name}
                                  ^ no initial_context field exists
POST /api/v1/public/embed/init    InitEmbedRequest = {token, context_variables}
                                  ^ the ONE supported injection point
```

So a console Test Call renders `{{initial_context.call_id}}` empty and the
tool's required presets refuse it. Making the console work would mean patching
Dograh core, which we do not do. This helper drives the same
`/public/embed/init` the public `/recovery` page uses, with a bootstrap minted
by the same trusted server-side code — no new trust surface.

### Usage

```bash
VOICE_DOGRAH_RECOVERY_TEST_MODE=true \
    python -m provisioning.recovery_test_bootstrap --workflow-id 1
```

### Containment

- **Off by default.** Only the exact string `true` enables it; `1`, `yes`, `on`
  and a development `NODE_ENV`/`ENVIRONMENT` all leave it off, so an unrelated
  flag can never switch on an unauthenticated bootstrap minter.
- **No identity, ever.** The bootstrap carries `call_id, purpose, aud, iat,
  exp, ver` and nothing else — no UPN, oid, employee id or mobile. The employee
  ID is spoken on the call and proven by Duo, exactly as for a real caller.
- **Fresh random `call_id`** per invocation, **300s TTL**, same signing secret
  and same verification path as `/recovery`.
- **Host-only.** It is a CLI needing the 0600 signing secret and the 0600
  Dograh API key; it is never reachable from a browser and takes no input from
  one.
- **No production fallback.** With the flag off it exits non-zero and a
  context-less Dograh call still fails closed.
