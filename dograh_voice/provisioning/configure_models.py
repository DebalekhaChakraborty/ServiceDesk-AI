"""Switch Dograh inference to GCP Vertex via ADC, and fail closed on fallback.

Targets the organization V2 (BYOK) surface, which is what actually decides
whether inference is billed to Dograh credits. `/user/configurations/user` is
only a derived read-only view and cannot switch the mode.

Refuses to leave a Dograh-managed provider in any slot that a realtime call
actually instantiates, so a silent fallback to Dograh credits cannot survive.
"""

from __future__ import annotations

import argparse
import json
import sys

from .dograh_client import DograhClient, redact
from .desired_state import desired_model_config, find_dograh_providers, vertex_services

# Slots a realtime (native-audio) call actually instantiates. In realtime mode
# Dograh does not build an STT or TTS service at all, so a residual `dograh`
# value in those slots is inert — it is reported loudly but does not fail the
# switch. The provider log proof at call time is the real arbiter.
ACTIVE_REALTIME_SLOTS = ("realtime", "llm")


class DograhFallbackDetected(RuntimeError):
    """Raised when a Dograh-managed provider is still active after a switch."""


def active_dograh_providers(effective: dict) -> list[str]:
    """Dograh-managed providers in slots a realtime call actually creates."""
    found = []
    for slot in ACTIVE_REALTIME_SLOTS:
        node = effective.get(slot)
        if isinstance(node, dict):
            found += [f"{slot}.{p}" for p in find_dograh_providers(node)]
    return found


def inactive_dograh_providers(effective: dict) -> list[str]:
    """Residual Dograh values in slots realtime mode never instantiates."""
    found = []
    for slot, node in (effective or {}).items():
        if slot in ACTIVE_REALTIME_SLOTS or not isinstance(node, dict):
            continue
        found += [f"{slot}.{p}" for p in find_dograh_providers(node)]
    return found


def snapshot(client: DograhClient) -> dict:
    """Masked snapshot of current configuration, safe to print or store."""
    return redact(client.get_model_config_v2() or {})


def apply(client: DograhClient, dry_run: bool = False) -> dict:
    before = client.get_model_config_v2() or {}
    before_cfg = before.get("configuration") or {}
    before_eff = before.get("effective_configuration") or {}
    desired = desired_model_config()

    print("--- BEFORE: configuration (masked) ---")
    print(json.dumps(redact(before_cfg), indent=2)[:1200])
    print(f"--- before mode        : {before_cfg.get('mode')}")
    print(f"--- before dograh(all) : {find_dograh_providers(before_eff) or 'none'}")

    # ADC contract: these must be ABSENT, not empty strings. An empty string
    # would be treated as a real credential by pipecat and skip the ADC path.
    for service in vertex_services(desired):
        for forbidden in ("credentials", "api_key"):
            assert forbidden not in service, (
                f"{service.get('provider')}.{forbidden} must be omitted so Vertex uses ADC"
            )
        assert service.get("location"), (
            f"{service.get('provider')}.location must be explicit; Dograh would "
            "otherwise fall back to us-east4, where the configured model 404s"
        )

    if dry_run:
        print("[dry-run] PUT /api/v1/organizations/model-configurations/v2")
        print(json.dumps(redact(desired), indent=2))
        return {
            "action": "would-update",
            "dry_run": True,
            "before_mode": before_cfg.get("mode"),
            "desired": desired,
        }

    client.put_model_config_v2(desired)

    after = client.get_model_config_v2() or {}
    after_cfg = after.get("configuration") or {}
    after_eff = after.get("effective_configuration") or {}
    active = active_dograh_providers(after_eff)
    inactive = inactive_dograh_providers(after_eff)

    print("--- AFTER: configuration (masked) ---")
    print(json.dumps(redact(after_cfg), indent=2)[:1500])
    print("--- AFTER: effective (masked) ---")
    print(json.dumps(redact(after_eff), indent=2)[:1500])
    print(f"--- after mode              : {after_cfg.get('mode')}")
    print(f"--- dograh in ACTIVE slots  : {active or 'none'}")
    print(f"--- dograh in unused slots  : {inactive or 'none'}")

    if active:
        raise DograhFallbackDetected(
            "Dograh-managed inference is still active after the switch "
            f"({active}). Refusing to proceed - this would bill Dograh credits. "
            "Investigate before placing any call."
        )
    if after_cfg.get("mode") != "byok":
        raise DograhFallbackDetected(
            f"Configuration mode is {after_cfg.get('mode')!r}, expected 'byok'. "
            "Dograh-managed inference would still be used."
        )
    if inactive:
        print(
            "WARNING: the slots above still name Dograh, but realtime mode does "
            "not instantiate them. Confirm against the provider log proof."
        )

    return {
        "action": "updated",
        "dry_run": False,
        "before_mode": before_cfg.get("mode"),
        "after_mode": after_cfg.get("mode"),
        "active_dograh": active,
        "inactive_dograh": inactive,
        "effective": after_eff,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Point Dograh inference at Vertex via ADC")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        apply(DograhClient(), dry_run=args.dry_run)
    except DograhFallbackDetected as exc:
        print(f"FAIL CLOSED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
