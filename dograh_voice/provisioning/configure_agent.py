"""Attach the tool + prompt to the ServiceDesk agent node, preserving everything else.

The workflow definition is fetched first and patched surgically: unrelated
nodes, edges, and settings are copied through untouched. The workflow id is
never assumed - it is resolved by name and must be confirmed.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from typing import Any

from .dograh_client import DograhClient, redact
from .desired_state import AGENT_PROMPT, TOOL_NAME

# Node types that carry an agent prompt + tools in Dograh v1.45.0. The live
# ServiceDesk workflow uses `startCall`; the others are accepted so a
# multi-node workflow keeps working without another schema archaeology pass.
AGENT_NODE_TYPES = {"startCall", "agentNode", "agent", "AgentNode"}

# Dograh stores attached tools on the node as `tool_uuids` (confirmed against
# the live workflow definition). An earlier draft of this script wrote `tools`,
# which Dograh silently ignores — the tool would have looked attached in git
# and done nothing on the call.
TOOLS_FIELD = "tool_uuids"


def resolve_workflow(client: DograhClient, name_hint: str | None, workflow_id: Any | None):
    """Find the target workflow. Never guesses when the choice is ambiguous."""
    if workflow_id is not None:
        return client.get_workflow(workflow_id)

    workflows = client.list_workflows()
    if not workflows:
        raise RuntimeError("No workflows found in Dograh.")

    if name_hint:
        matches = [w for w in workflows if name_hint.lower() in str(w.get("name", "")).lower()]
    else:
        matches = workflows

    if len(matches) != 1:
        listing = ", ".join(f"{w.get('id')}:{w.get('name')}" for w in workflows)
        raise RuntimeError(
            f"Could not unambiguously resolve the workflow (matched {len(matches)}). "
            f"Pass --workflow-id explicitly. Available: {listing}"
        )
    return client.get_workflow(matches[0].get("id"))


def _nodes_of(definition: dict) -> list[dict]:
    return definition.get("nodes") or []


def find_agent_nodes(definition: dict) -> list[dict]:
    return [n for n in _nodes_of(definition) if n.get("type") in AGENT_NODE_TYPES]


def patch_definition(
    definition: dict, tool_uuid: str, node_id: str | None, set_prompt: bool
) -> tuple[dict, list[str]]:
    """Return (new_definition, changes). Deep-copied; unrelated structure preserved."""
    new = copy.deepcopy(definition)
    changes: list[str] = []

    agents = find_agent_nodes(new)
    if not agents:
        raise RuntimeError("No agent node found in the workflow definition.")

    if node_id:
        targets = [n for n in agents if str(n.get("id")) == str(node_id)]
        if not targets:
            raise RuntimeError(f"Agent node id {node_id!r} not found.")
    elif len(agents) == 1:
        targets = agents
    else:
        ids = [n.get("id") for n in agents]
        raise RuntimeError(
            f"Multiple agent nodes {ids}; pass --node-id so only the intended one changes."
        )

    node = targets[0]
    data = node.setdefault("data", {})

    tools = data.get(TOOLS_FIELD)
    if not isinstance(tools, list):
        tools = []
    if tool_uuid not in tools:
        tools.append(tool_uuid)
        data[TOOLS_FIELD] = tools
        changes.append(f"node[{node.get('id')}].{TOOLS_FIELD} += {tool_uuid}")

    if set_prompt and data.get("prompt") != AGENT_PROMPT:
        data["prompt"] = AGENT_PROMPT
        changes.append(f"node[{node.get('id')}].prompt updated")

    return new, changes


def apply(
    client: DograhClient,
    tool_uuid: str,
    name_hint: str | None = None,
    workflow_id: Any | None = None,
    node_id: str | None = None,
    set_prompt: bool = True,
    dry_run: bool = False,
) -> dict:
    workflow = resolve_workflow(client, name_hint, workflow_id)
    wid = workflow.get("id")
    definition = workflow.get("workflow_definition") or workflow.get("definition") or {}
    if isinstance(definition, str):
        definition = json.loads(definition)

    before_nodes = len(_nodes_of(definition))
    new_def, changes = patch_definition(definition, tool_uuid, node_id, set_prompt)
    after_nodes = len(_nodes_of(new_def))

    assert before_nodes == after_nodes, "node count must not change"

    if not changes:
        print(f"UNCHANGED workflow id={wid} (name={workflow.get('name')!r})")
        return {"action": "noop", "workflow_id": wid, "changes": []}

    print(f"workflow id={wid} name={workflow.get('name')!r} changes={changes}")
    if dry_run:
        print("[dry-run] PUT /api/v1/workflow/%s (not applied)" % wid)
        return {"action": "would-update", "workflow_id": wid, "changes": changes,
                "dry_run": True}

    client.update_workflow(wid, {"workflow_definition": new_def})
    validation = client.validate_workflow(wid)
    print(f"UPDATED workflow id={wid}; validation={json.dumps(redact(validation))[:300]}")
    return {"action": "updated", "workflow_id": wid, "changes": changes,
            "validation": validation}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Attach the ServiceDesk tool to the agent node")
    ap.add_argument("--tool-uuid", required=True)
    ap.add_argument("--workflow-id")
    ap.add_argument("--name-hint", default=None, help="substring match on workflow name")
    ap.add_argument("--node-id", default=None)
    ap.add_argument("--keep-prompt", action="store_true", help="do not overwrite the prompt")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    apply(
        DograhClient(),
        tool_uuid=args.tool_uuid,
        name_hint=args.name_hint,
        workflow_id=args.workflow_id,
        node_id=args.node_id,
        set_prompt=not args.keep_prompt,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
