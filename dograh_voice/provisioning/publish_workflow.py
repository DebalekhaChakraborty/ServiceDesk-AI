"""Promote the working draft to published, with a pre-publish safety diff.

Only the published version is executed by production triggers (telephony,
/public/agent/workflow/{uuid}, embed). The in-browser test call runs the draft
-- api/routes/workflow.py passes use_draft=True -- so a workflow can test
perfectly while production still runs an older definition.

This script refuses to publish when the draft would lose something the
published version already has, which is the failure mode worth guarding: a
silent regression in what production actually runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .dograh_client import DograhClient

# Node fields that are transient editor state or canvas layout. Differences in
# these are noise and never block a publish.
COSMETIC_NODE_FIELDS = {
    "dragging", "hovered_through_edge", "invalid", "selected",
    "selected_through_edge", "validationMessage", "measured", "position",
}


def _nodes_by_id(definition: dict) -> dict[str, dict]:
    return {str(n.get("id")): n for n in (definition.get("nodes") or [])}


def _meaningful(node: dict) -> dict[str, Any]:
    data = {k: v for k, v in (node.get("data") or {}).items()
            if k not in COSMETIC_NODE_FIELDS}
    return {"type": node.get("type"), "data": data}


def regressions(published: dict, draft: dict) -> list[str]:
    """Things the draft would REMOVE or blank relative to what is published.

    Additions are expected (that is the point of publishing); losses are not.
    """
    problems: list[str] = []
    pub_nodes, draft_nodes = _nodes_by_id(published), _nodes_by_id(draft)

    for node_id in pub_nodes:
        if node_id not in draft_nodes:
            problems.append(f"node {node_id} present in published, missing from draft")
            continue
        pub_data = _meaningful(pub_nodes[node_id])["data"]
        draft_data = _meaningful(draft_nodes[node_id])["data"]
        for key, pub_value in pub_data.items():
            if key not in draft_data:
                problems.append(f"node {node_id}.{key} would be dropped")
            elif pub_value and not draft_data[key]:
                problems.append(f"node {node_id}.{key} would be blanked")

    pub_edges = published.get("edges") or []
    if len(draft.get("edges") or []) < len(pub_edges):
        problems.append("draft has fewer edges than published")
    return problems


def apply(client: DograhClient, workflow_id: int, expect_tool_uuid: str | None = None,
          dry_run: bool = False) -> dict:
    versions = client.list_workflow_versions(workflow_id)
    draft = next((v for v in versions if v.get("status") == "draft"), None)
    published = next((v for v in versions if v.get("status") == "published"), None)

    if draft is None:
        print(f"No draft for workflow {workflow_id}; nothing to publish.")
        return {"action": "noop", "reason": "no-draft"}

    draft_def = draft.get("workflow_json") or {}
    pub_def = (published or {}).get("workflow_json") or {}

    print(f"draft     v{draft.get('version_number')} created={draft.get('created_at')}")
    if published:
        print(f"published v{published.get('version_number')} at={published.get('published_at')}")

    if expect_tool_uuid:
        attached = [n.get("id") for n in (draft_def.get("nodes") or [])
                    if expect_tool_uuid in ((n.get("data") or {}).get("tool_uuids") or [])]
        if not attached:
            raise RuntimeError(
                f"Refusing to publish: tool {expect_tool_uuid} is not attached to any "
                "draft node. Publishing would ship an agent with no ServiceDesk tool."
            )
        print(f"  draft nodes carrying {expect_tool_uuid[:8]}...: {attached}")

    problems = regressions(pub_def, draft_def)
    if problems:
        raise RuntimeError(
            "Refusing to publish - the draft would regress the published "
            f"definition:\n  - " + "\n  - ".join(problems)
        )
    print("  pre-publish check: no regressions against the published definition")

    if dry_run:
        print(f"[dry-run] POST /api/v1/workflow/{workflow_id}/publish (not applied)")
        return {"action": "would-publish", "dry_run": True,
                "draft_version": draft.get("version_number")}

    result = client.publish_workflow(workflow_id)
    after = client.list_workflow_versions(workflow_id)
    now_published = [v for v in after if v.get("status") == "published"]
    print(f"PUBLISHED workflow {workflow_id}; "
          f"published versions now: {[v.get('version_number') for v in now_published]}")
    return {"action": "published", "workflow_id": workflow_id,
            "published_versions": [v.get("version_number") for v in now_published],
            "result": result}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Publish the working Dograh draft")
    ap.add_argument("--workflow-id", type=int, default=1)
    ap.add_argument("--expect-tool-uuid", default=None,
                    help="refuse to publish unless this tool is attached")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        apply(DograhClient(), args.workflow_id, args.expect_tool_uuid, args.dry_run)
    except RuntimeError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
