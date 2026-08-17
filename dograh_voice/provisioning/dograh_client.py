"""Minimal client for the Dograh v1.45.0 REST API.

Auth is `X-API-Key`, resolved from the environment or a git-ignored file. The
key is never hard-coded, never logged, and never echoed in diffs.

Endpoints used (all confirmed present in the running deployment's
/api/v1/openapi.json):

    GET/POST /api/v1/tools/
    GET/PUT  /api/v1/tools/{tool_uuid}
    GET      /api/v1/workflow/fetch
    GET      /api/v1/workflow/fetch/{workflow_id}
    PUT      /api/v1/workflow/{workflow_id}
    POST     /api/v1/workflow/{workflow_id}/validate
    GET      /api/v1/workflow/{workflow_id}/versions
    POST     /api/v1/workflow/{workflow_id}/publish
    GET/PUT  /api/v1/organizations/model-configurations/v2
    GET      /api/v1/organizations/model-configurations/v2/defaults
    GET      /api/v1/organizations/billing/credits
    GET      /api/v1/user/configurations/defaults
    GET      /api/v1/user/configurations/user
    GET      /api/v1/user/configurations/user/validate
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:8001"
KEY_ENV = "DOGRAH_API_KEY"
# Git-ignored (runtime/ is ignored wholesale except whitelisted files).
KEY_FILE = Path(__file__).resolve().parents[1] / "runtime" / ".dograh_api_key"

SECRET_FIELDS = {
    "api_key", "apikey", "credentials", "secret", "token", "password",
    "service_key", "x-api-key", "authorization",
}


class DograhAuthMissing(RuntimeError):
    pass


class DograhApiError(RuntimeError):
    def __init__(self, status: int, detail: str = "") -> None:
        super().__init__(f"Dograh API returned {status}")
        self.status = status
        # Kept short and free of request context so nothing sensitive surfaces.
        self.detail = detail[:200]


def load_api_key() -> str:
    """Resolve the API key from env, else the git-ignored file. Never logged."""
    key = os.getenv(KEY_ENV, "").strip()
    if key:
        return key
    if KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
        if key:
            return key
    raise DograhAuthMissing(
        f"No Dograh API key. Set {KEY_ENV} or write it to {KEY_FILE} (mode 0600). "
        "See provisioning/README.md for the one-time bootstrap."
    )


def redact(obj: Any) -> Any:
    """Deep-copy with secret-looking values replaced. Used for every diff/log."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SECRET_FIELDS and v not in (None, ""):
                out[k] = "<redacted>"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


class DograhClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("DOGRAH_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self._api_key = api_key or load_api_key()
        self._client = client or httpx.Client(timeout=timeout)

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self._api_key, "Content-Type": "application/json"}

    def _request(self, method: str, path: str, **kw) -> Any:
        resp = self._client.request(
            method, f"{self.base_url}{path}", headers=self._headers(), **kw
        )
        if resp.status_code >= 400:
            raise DograhApiError(resp.status_code, resp.text)
        if not resp.content:
            return None
        return resp.json()

    # -- tools ------------------------------------------------------------
    def list_tools(self) -> list[dict]:
        data = self._request("GET", "/api/v1/tools/")
        if isinstance(data, dict):
            return data.get("tools") or data.get("items") or []
        return data or []

    def find_tool_by_name(self, name: str) -> dict | None:
        """Exact-name match. Never fuzzy — a near-match must create, not clobber."""
        for tool in self.list_tools():
            if tool.get("name") == name:
                return tool
        return None

    def create_tool(self, payload: dict) -> dict:
        return self._request("POST", "/api/v1/tools/", json=payload)

    def update_tool(self, tool_uuid: str, payload: dict) -> dict:
        return self._request("PUT", f"/api/v1/tools/{tool_uuid}", json=payload)

    # -- workflows --------------------------------------------------------
    def list_workflows(self) -> list[dict]:
        data = self._request("GET", "/api/v1/workflow/fetch")
        if isinstance(data, dict):
            return data.get("workflows") or data.get("items") or []
        return data or []

    def get_workflow(self, workflow_id: Any) -> dict:
        return self._request("GET", f"/api/v1/workflow/fetch/{workflow_id}")

    def update_workflow(self, workflow_id: Any, payload: dict) -> dict:
        return self._request("PUT", f"/api/v1/workflow/{workflow_id}", json=payload)

    def validate_workflow(self, workflow_id: Any, payload: dict | None = None) -> Any:
        return self._request(
            "POST", f"/api/v1/workflow/{workflow_id}/validate", json=payload or {}
        )

    def list_workflow_versions(self, workflow_id: Any) -> list[dict]:
        return self._request("GET", f"/api/v1/workflow/{workflow_id}/versions") or []

    def publish_workflow(self, workflow_id: Any) -> Any:
        """Promote the draft to published.

        Only the published version is executed by production triggers
        (telephony, /public/agent/workflow/{uuid}). The in-browser test call
        runs the draft — api/routes/workflow.py passes use_draft=True — so
        publishing is required for anything beyond testing.
        """
        return self._request("POST", f"/api/v1/workflow/{workflow_id}/publish", json={})

    # -- model configuration (organization V2 / BYOK) ---------------------
    # This is the surface that decides whether inference is billed to Dograh
    # credits. /user/configurations/user is the derived, read-only view of it
    # and has no PUT that can switch the mode.
    def get_model_config_v2(self) -> dict:
        return self._request("GET", "/api/v1/organizations/model-configurations/v2")

    def put_model_config_v2(self, payload: dict) -> dict:
        return self._request(
            "PUT", "/api/v1/organizations/model-configurations/v2", json=payload
        )

    def get_model_config_v2_defaults(self) -> dict:
        return self._request(
            "GET", "/api/v1/organizations/model-configurations/v2/defaults"
        )

    # -- embed tokens ------------------------------------------------------
    def get_embed_tokens(self, workflow_id: Any) -> Any:
        return self._request("GET", f"/api/v1/workflow/{workflow_id}/embed-token")

    def create_embed_token(self, workflow_id: Any, payload: dict) -> dict:
        return self._request(
            "POST", f"/api/v1/workflow/{workflow_id}/embed-token", json=payload
        )

    def delete_embed_token(self, workflow_id: Any) -> Any:
        return self._request("DELETE", f"/api/v1/workflow/{workflow_id}/embed-token")

    def get_credits(self) -> dict:
        return self._request("GET", "/api/v1/organizations/billing/credits")

    # -- derived user-level view ------------------------------------------
    def get_config_defaults(self) -> dict:
        return self._request("GET", "/api/v1/user/configurations/defaults")

    def get_user_config(self) -> dict:
        return self._request("GET", "/api/v1/user/configurations/user")

    def validate_user_config(self) -> Any:
        return self._request("GET", "/api/v1/user/configurations/user/validate")
