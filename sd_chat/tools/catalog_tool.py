# Keeping it optional for debugging, user help, or compliance introspection.
# Our generic_planner_tool + action registry fully replaces its functional purpose.

import os, json, glob

REG_DIR = os.getenv("ACTION_REGISTRY_DIR", os.path.join(os.path.dirname(__file__), "..", "action_registry"))

def catalog_tool():
    """Return all available actions with basic info."""
    catalog = []
    for path in glob.glob(os.path.join(REG_DIR, "*.json")):
        try:
            with open(path) as f:
                obj = json.load(f)
                catalog.append({
                    "id": obj.get("id"),
                    "title": obj.get("title"),
                    "tool": obj.get("tool"),
                    "tags": obj.get("tags"),
                    "requires": obj.get("requires"),
                    "provides": obj.get("provides")
                })
        except Exception:
            pass
    return {"status": "ok", "catalog": catalog}