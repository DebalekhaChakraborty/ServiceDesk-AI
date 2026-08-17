"""Idempotently create or update the `servicedesk_voice_turn` tool.

Repeatable: finds by exact name, creates only if absent, updates only when the
desired configuration actually differs. Never creates duplicates.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys

from .dograh_client import DograhClient, redact
from .desired_state import TOOL_NAME, desired_tool_payload

# Keys inside definition.config that Dograh populates but this project does not
# manage. They are carried through untouched on update so a PUT built from the
# desired state cannot silently reset them to defaults.
UNMANAGED_CONFIG_KEYS = (
    "credential_uuid", "preset_parameters", "customMessage", "customMessageType",
    "customMessageRecordingId", "body_template",
)


def merge_payload(existing: dict, desired: dict) -> dict:
    """Desired state on top of the live tool, preserving unmanaged fields."""
    merged = copy.deepcopy(desired)
    live_cfg = ((existing.get("definition") or {}).get("config") or {})
    cfg = merged["definition"]["config"]
    for key in UNMANAGED_CONFIG_KEYS:
        if key in live_cfg and key not in cfg:
            cfg[key] = live_cfg[key]
    return merged


def diff(existing: dict, desired: dict) -> list[str]:
    """Fields this project manages that differ from the live tool."""
    changes = []
    for field in ("name", "description"):
        if existing.get(field) != desired.get(field):
            changes.append(field)

    live_cfg = ((existing.get("definition") or {}).get("config") or {})
    want_cfg = desired["definition"]["config"]
    for key, want in want_cfg.items():
        if live_cfg.get(key) != want:
            changes.append(f"definition.config.{key}")
    return changes


def apply(client: DograhClient, dry_run: bool = False) -> dict:
    desired = desired_tool_payload()
    existing = client.find_tool_by_name(TOOL_NAME)

    if existing is None:
        if dry_run:
            print(f"[dry-run] CREATE tool {TOOL_NAME}")
            print(json.dumps(redact(desired), indent=2))
            return {"action": "create", "dry_run": True, "tool_uuid": None}
        created = client.create_tool(desired)
        uuid = created.get("tool_uuid") or created.get("uuid")
        print(f"CREATED tool {TOOL_NAME} uuid={uuid}")
        return {"action": "create", "dry_run": False, "tool_uuid": uuid}

    uuid = existing.get("tool_uuid") or existing.get("uuid")
    changed = diff(existing, desired)
    if not changed:
        print(f"UNCHANGED tool {TOOL_NAME} uuid={uuid}")
        return {"action": "noop", "dry_run": dry_run, "tool_uuid": uuid}

    payload = merge_payload(existing, desired)

    if dry_run:
        print(f"[dry-run] UPDATE tool {TOOL_NAME} uuid={uuid} fields={changed}")
        for field in changed:
            if field.startswith("definition.config."):
                key = field.split(".")[-1]
                live = ((existing.get("definition") or {}).get("config") or {}).get(key)
                print(f"    {key}: {json.dumps(live)[:80]}  ->  "
                      f"{json.dumps(payload['definition']['config'][key])[:80]}")
            else:
                print(f"    {field}: {json.dumps(existing.get(field))[:80]}  ->  "
                      f"{json.dumps(payload.get(field))[:80]}")
        return {"action": "update", "dry_run": True, "tool_uuid": uuid, "fields": changed}

    client.update_tool(uuid, payload)
    print(f"UPDATED tool {TOOL_NAME} uuid={uuid} fields={changed}")
    return {"action": "update", "dry_run": False, "tool_uuid": uuid, "fields": changed}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Provision the ServiceDesk voice tool")
    ap.add_argument("--dry-run", action="store_true", help="show changes, apply nothing")
    args = ap.parse_args(argv)
    result = apply(DograhClient(), dry_run=args.dry_run)
    return 0 if result["action"] != "error" else 1


if __name__ == "__main__":
    sys.exit(main())
