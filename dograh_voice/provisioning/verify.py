"""Read-only verification of the provisioned state. Mutates nothing."""

from __future__ import annotations

import argparse
import json
import sys

from .configure_models import active_dograh_providers, inactive_dograh_providers
from .dograh_client import DograhClient, redact
from .desired_state import TOOL_NAME, TOOL_TIMEOUT_MS, find_dograh_providers


def run(client: DograhClient, workflow_id: int = 1) -> int:
    failures = 0

    def fail(msg: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL: {msg}")

    print("=== TOOL ===")
    tools = [t for t in client.list_tools() if t.get("name") == TOOL_NAME]
    tool_uuid = None
    if len(tools) == 1:
        t = tools[0]
        tool_uuid = t.get("tool_uuid")
        cfg = (t.get("definition") or {}).get("config", {})
        params = cfg.get("parameters") or []
        print(f"  uuid={tool_uuid} url={cfg.get('url')} "
              f"timeout_ms={cfg.get('timeout_ms')} "
              f"params={[p.get('name') for p in params]}")
        if any(p.get("name") == "voice_session_id" for p in params):
            fail("voice_session_id must not be an LLM-filled parameter")
        if cfg.get("timeout_ms") != TOOL_TIMEOUT_MS:
            fail(f"timeout_ms is {cfg.get('timeout_ms')}, expected {TOOL_TIMEOUT_MS}")
    else:
        fail(f"expected exactly 1 tool named {TOOL_NAME}, found {len(tools)}")

    print("=== WORKFLOW ===")
    wf = client.get_workflow(workflow_id)
    definition = wf.get("workflow_definition") or {}
    if isinstance(definition, str):
        definition = json.loads(definition)
    nodes = definition.get("nodes") or []
    attached = [n.get("id") for n in nodes
                if tool_uuid in ((n.get("data") or {}).get("tool_uuids") or [])]
    print(f"  id={workflow_id} name={wf.get('name')!r} nodes={len(nodes)} "
          f"version={wf.get('version_number')} status={wf.get('version_status')}")
    print(f"  nodes carrying the tool: {attached or 'NONE'}")
    if not attached:
        fail(f"{TOOL_NAME} is not attached to any node (field is `tool_uuids`)")

    versions = client.list_workflow_versions(workflow_id)
    published = [v for v in versions if v.get("status") == "published"]
    for v in versions:
        vnodes = (v.get("workflow_json") or {}).get("nodes", [])
        vtools = [u for n in vnodes for u in ((n.get("data") or {}).get("tool_uuids") or [])]
        print(f"  v{v.get('version_number')} {v.get('status'):9s} tool_attached="
              f"{tool_uuid in vtools}")
    if published and not any(
        tool_uuid in [u for n in (v.get("workflow_json") or {}).get("nodes", [])
                      for u in ((n.get("data") or {}).get("tool_uuids") or [])]
        for v in published
    ):
        # Not a failure: the in-browser test call runs the draft. It only bites
        # once a production trigger (telephony / public agent) is used.
        print("  NOTE: the PUBLISHED version has no tool attached. Browser test "
              "calls use the draft, but production triggers would not.")

    print("=== MODEL CONFIG (V2) ===")
    v2 = client.get_model_config_v2() or {}
    cfg = v2.get("configuration") or {}
    eff = v2.get("effective_configuration") or {}
    print(json.dumps(redact(eff), indent=2)[:1200])

    if cfg.get("mode") != "byok":
        fail(f"mode is {cfg.get('mode')!r}, expected 'byok'")

    active = active_dograh_providers(eff)
    inactive = inactive_dograh_providers(eff)
    if active:
        fail(f"Dograh-managed inference active in: {active}")
    else:
        print("  OK: no Dograh-managed provider in any active slot")
    if inactive:
        print(f"  NOTE: residual Dograh values in unused slots: {inactive}")
    if find_dograh_providers(cfg):
        fail(f"stored configuration still names Dograh: {find_dograh_providers(cfg)}")

    for slot in ("realtime", "llm"):
        node = eff.get(slot) or {}
        if node.get("credentials") or node.get("api_key"):
            fail(f"{slot} carries an explicit credential; ADC expects none")
        if not node.get("location"):
            fail(f"{slot}.location is empty; Dograh would fall back to us-east4")

    print("=== CREDITS ===")
    credits = client.get_credits() or {}
    print(f"  used={credits.get('total_credits_used')} "
          f"remaining={credits.get('remaining_credits')} "
          f"quota={credits.get('total_quota')}")

    print(f"=== {'PASS' if failures == 0 else f'{failures} FAILURE(S)'} ===")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify provisioned Dograh state")
    ap.add_argument("--workflow-id", type=int, default=1)
    args = ap.parse_args(argv)
    return run(DograhClient(), workflow_id=args.workflow_id)


if __name__ == "__main__":
    sys.exit(main())
