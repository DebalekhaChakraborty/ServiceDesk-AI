"""Config-as-code provisioning for the Dograh ServiceDesk voice agent.

Not an ADK agent package: never expose a `root_agent` here, and never add an
__init__.py to dograh_voice/ itself (the ServiceDesk server scans the repo root
as its agents dir).
"""

__all__ = [
    "dograh_client",
    "desired_state",
    "configure_tool",
    "configure_agent",
    "configure_models",
    "verify",
]
