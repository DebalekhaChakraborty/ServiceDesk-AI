"""DEVELOPER-ONLY bootstrap for the canonical EXTERNAL RECOVERY journey.

Why this file exists
--------------------
Dograh's native Test/Run button cannot carry trusted context. The live v1.45
API is explicit about it:

    POST /api/v1/workflow/{id}/runs   body = CreateWorkflowRunRequest
                                      required = ["mode", "name"]   <- no context

There is no `initial_context` field to populate, so a console Test Call always
renders `{{initial_context.call_id}}` empty and the tool's required presets
reject it. That is the security boundary working, and making the console able
to inject context would mean patching Dograh core, which we will not do.

The ONLY supported injection point in this build is the same one the public
recovery page already uses:

    POST /api/v1/public/embed/init    body = InitEmbedRequest
                                      properties = ["token", "context_variables"]
                                      -> workflow_run.initial_context

So this module does not invent a channel. It drives that exact endpoint with a
bootstrap minted by the same trusted server-side code as `/recovery`, giving a
developer the canonical external-caller journey with no new trust surface.

What it deliberately does NOT do
--------------------------------
* It asserts NO employee identity. The bootstrap carries call_id, purpose,
  aud, iat, exp and ver, and nothing else - identical to a real external
  caller. The employee id is spoken on the call and proven by Duo.
* It never runs from browser input. It is a CLI on the host, and it needs the
  0600 signing secret and the 0600 Dograh API key to do anything at all.
* It has no production fallback. With the mode flag off it refuses, and a
  context-less Dograh call keeps failing closed exactly as before.

Usage:

    VOICE_DOGRAH_RECOVERY_TEST_MODE=true \\
        python -m provisioning.recovery_test_bootstrap --workflow-id 1
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional

import httpx

from voice_gateway.identity import (
    PURPOSE_RECOVERY,
    load_signing_secret,
    mint_recovery_bootstrap,
    new_call_id,
)

from .dograh_client import DEFAULT_BASE_URL, DograhClient

# Off unless explicitly and exactly enabled. Deliberately its own variable:
# NODE_ENV, ENVIRONMENT=local, or a debug flag must never switch this on as a
# side effect of something else being set.
MODE_ENV = "VOICE_DOGRAH_RECOVERY_TEST_MODE"

# Short on purpose. A developer bootstrap is used within seconds of minting;
# a long-lived one lying around in a terminal is a bearer credential.
DEV_TTL_SECONDS = 300


class DevModeDisabled(RuntimeError):
    """The developer bootstrap was invoked without being explicitly enabled."""


def dev_mode_enabled(env: Optional[dict] = None) -> bool:
    """True only for an exact opt-in. Everything else is false.

    Not `bool(value)` and not a truthy-string helper shared with other flags:
    an unauthenticated recovery bootstrap generator is exactly the thing that
    should refuse to switch itself on because some unrelated variable happened
    to be set.
    """
    source = os.environ if env is None else env
    return source.get(MODE_ENV, "").strip().lower() == "true"


def require_dev_mode(env: Optional[dict] = None) -> None:
    if not dev_mode_enabled(env):
        raise DevModeDisabled(
            f"{MODE_ENV} is not exactly 'true'; refusing to mint a developer "
            "recovery bootstrap"
        )


def mint_dev_recovery_context(
    secret: Optional[str] = None,
    ttl_seconds: int = DEV_TTL_SECONDS,
) -> dict[str, str]:
    """The two context variables, and nothing else.

    Returns exactly the shape the browser widget sends, so the developer path
    and the public path put identical keys into workflow_run.initial_context.
    """
    require_dev_mode()
    call_id = new_call_id()                       # fresh, server-generated
    token = mint_recovery_bootstrap(
        call_id, secret or load_signing_secret(), ttl_seconds=ttl_seconds
    )
    return {"call_id": call_id, "voice_identity_token": token}


def active_embed_token(client: DograhClient, workflow_id: int) -> dict[str, Any]:
    """The active embed token RECORD, so its allowed origin travels with it."""
    tokens = client.get_embed_tokens(workflow_id)
    tokens = tokens if isinstance(tokens, list) else [tokens]
    active = [t for t in tokens if t and t.get("is_active")]
    if not active:
        raise RuntimeError(f"no active embed token for workflow {workflow_id}")
    return active[0]


def init_embed_session(
    embed_token: str,
    context: dict[str, str],
    origin: str,
    base_url: str = DEFAULT_BASE_URL,
) -> dict[str, Any]:
    """POST /api/v1/public/embed/init — the one supported context injection.

    Dograh enforces the token's `allowed_domains` against the Origin header
    (a wrong origin is a 403), so the developer path must present the same
    origin the browser would. It is read off the token record rather than
    hard-coded: a hard-coded origin would silently rot the moment the token is
    reissued for a different domain.
    """
    response = httpx.post(
        f"{base_url}/api/v1/public/embed/init",
        json={"token": embed_token, "context_variables": context},
        headers={"Origin": origin},
        timeout=30.0,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"embed/init returned HTTP {response.status_code} for origin {origin!r}"
        )
    return response.json()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="recovery_test_bootstrap",
        description="DEVELOPER ONLY. Start the canonical external-recovery "
                    "journey with a server-minted bootstrap carrying no identity.",
    )
    parser.add_argument("--workflow-id", type=int, default=1)
    parser.add_argument("--base-url", default=os.getenv("DOGRAH_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--ttl", type=int, default=DEV_TTL_SECONDS)
    args = parser.parse_args(argv)

    try:
        require_dev_mode()
    except DevModeDisabled as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    context = mint_dev_recovery_context(ttl_seconds=args.ttl)
    client = DograhClient(base_url=args.base_url)
    token_record = active_embed_token(client, args.workflow_id)
    domains = token_record.get("allowed_domains") or []
    if not domains:
        raise RuntimeError("embed token has no allowed_domains; refusing to guess one")
    origin = str(domains[0])
    session = init_embed_session(
        str(token_record["token"]), context, origin, args.base_url
    )

    # The token itself is never printed: it is a bearer credential for one call.
    print("DEVELOPER external-recovery bootstrap (no employee identity asserted)")
    print(f"  workflow_id      : {args.workflow_id}")
    print(f"  embed origin     : {origin}")
    print(f"  call_id          : {context['call_id']}")
    print(f"  bootstrap token  : <withheld> (purpose={PURPOSE_RECOVERY}, ttl={args.ttl}s)")
    print(f"  workflow_run_id  : {session.get('workflow_run_id')}")
    print(f"  session_token    : <withheld>")
    print()
    print("initial_context now carries exactly: "
          f"{sorted(context)}")
    print("Speak an employee ID on the call; Duo decides who the caller is.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
