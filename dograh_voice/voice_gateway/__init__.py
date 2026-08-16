"""Dograh -> ServiceDesk voice gateway.

Deliberately NOT an ADK agent package. The ServiceDesk server scans the repo
root as its agents dir, so this package must never expose a `root_agent`, and
`dograh_voice/` itself must never gain an `__init__.py`.
"""

__all__ = ["config", "models", "session", "servicedesk_client", "app"]
