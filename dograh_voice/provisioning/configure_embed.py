"""Create/inspect the Dograh embed token for the employee portal.

The embed token is what lets the Entra-authenticated portal page start a voice
call against the PUBLISHED workflow without exposing the Dograh console or any
Dograh credential to the browser.

Flow at runtime:

    portal page  --POST /api/v1/public/embed/init {token, context_variables}
                 --> {session_token, workflow_run_id, config}

`context_variables` land in workflow_run.initial_context, which is exactly
where the tool's preset parameters read call_id and voice_identity_token from.

The token is PUBLIC (it ships to the browser), so its only real defences are
the allowed-domain restriction and its expiry. Wildcards are refused here.
"""

from __future__ import annotations

import argparse
import json
import sys

from .dograh_client import DograhClient, redact

DEFAULT_EXPIRES_DAYS = 30


def validate_domains(domains: list[str]) -> None:
    """Refuse anything that would let an arbitrary page start a call."""
    if not domains:
        raise ValueError("at least one allowed domain is required")
    for domain in domains:
        value = (domain or "").strip()
        if not value:
            raise ValueError("empty domain entry")
        if "*" in value:
            raise ValueError(f"wildcard domain {value!r} is not permitted")
        if value in {"localhost", "127.0.0.1"}:
            # Allowed, but only with an explicit scheme+port so it cannot match
            # any other local service.
            raise ValueError(
                f"{value!r} is too broad; use the full origin e.g. http://localhost:8080"
            )
        if not value.startswith(("http://", "https://")):
            raise ValueError(f"domain {value!r} must be a full origin including scheme")


def find_existing(client: DograhClient, workflow_id: int) -> list[dict]:
    try:
        data = client.get_embed_tokens(workflow_id)
    except Exception:
        return []
    if isinstance(data, dict):
        return data.get("tokens") or data.get("items") or ([data] if data.get("token") else [])
    return data or []


def apply(client: DograhClient, workflow_id: int, domains: list[str],
          expires_in_days: int = DEFAULT_EXPIRES_DAYS, dry_run: bool = False) -> dict:
    validate_domains(domains)

    existing = find_existing(client, workflow_id)
    active = [t for t in existing if t.get("is_active")]
    for token in active:
        print(f"  existing token id={token.get('id')} "
              f"domains={token.get('allowed_domains')} "
              f"expires={token.get('expires_at')} usage={token.get('usage_count')}")

    matching = [t for t in active if sorted(t.get("allowed_domains") or []) == sorted(domains)]
    if matching:
        print(f"UNCHANGED embed token id={matching[0].get('id')} already allows {domains}")
        return {"action": "noop", "token_id": matching[0].get("id"),
                "allowed_domains": domains}

    payload = {
        "allowed_domains": domains,
        "expires_in_days": expires_in_days,
        # auto_start=false: the employee presses a button, so the microphone is
        # never opened by page load alone.
        "settings": {"widget_type": "voice", "auto_start": False},
    }

    if dry_run:
        print(f"[dry-run] POST /api/v1/workflow/{workflow_id}/embed-token")
        print(json.dumps(payload, indent=2))
        return {"action": "would-create", "dry_run": True, "allowed_domains": domains}

    created = client.create_embed_token(workflow_id, payload)
    print(f"CREATED embed token id={created.get('id')} domains={created.get('allowed_domains')} "
          f"expires={created.get('expires_at')}")
    # The token value itself is deliberately NOT printed: it is public in the
    # sense that the browser receives it, but it should not sit in a terminal
    # transcript or CI log. Read it back explicitly when wiring the portal.
    return {"action": "created", "token_id": created.get("id"),
            "allowed_domains": created.get("allowed_domains"),
            "expires_at": created.get("expires_at")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Configure the Dograh voice embed token")
    ap.add_argument("--workflow-id", type=int, default=1)
    ap.add_argument("--domain", action="append", required=True,
                    help="full allowed origin, repeatable; wildcards refused")
    ap.add_argument("--expires-in-days", type=int, default=DEFAULT_EXPIRES_DAYS)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        apply(DograhClient(), args.workflow_id, args.domain,
              args.expires_in_days, args.dry_run)
    except ValueError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
