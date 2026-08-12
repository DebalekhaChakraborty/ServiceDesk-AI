from typing import Dict, Any, List, Optional, Set
import os
import requests
import msal  # type: ignore
from google.adk.tools import FunctionTool, ToolContext
import secrets
import string
from .email_tool import send_email_via_gmail
from .policy_tool import (
    AAD_MANAGER_LOOKUP_STATE_KEY,
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
    ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY,
    consume_account_access_authorization,
)


# ==============================================================================
# Configuration
# ==============================================================================

AAD_TENANT_ID = os.getenv("AAD_TENANT_ID", "")
AAD_CLIENT_ID = os.getenv("AAD_CLIENT_ID", "")
AAD_CLIENT_SECRET = os.getenv("AAD_CLIENT_SECRET", "")
GRAPH_BASE_URL = os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


# ==============================================================================
# Helpers: Graph auth & HTTP
# ==============================================================================

def _graph_is_configured() -> bool:
    """Check that the basic env vars are present."""
    return bool(AAD_TENANT_ID and AAD_CLIENT_ID and AAD_CLIENT_SECRET)


def _get_graph_token() -> str:
    """
    Acquire an application token for Microsoft Graph using client credentials flow.

    Raises:
        RuntimeError with a detailed message if configuration is missing
        or MSAL fails to get a token.
    """
    if not _graph_is_configured():
        raise RuntimeError(
            "CONFIG_MISSING: AAD_TENANT_ID / AAD_CLIENT_ID / AAD_CLIENT_SECRET "
            "must all be set in the environment."
        )

    authority = f"https://login.microsoftonline.com/{AAD_TENANT_ID}"

    try:
        app = msal.ConfidentialClientApplication(
            client_id=AAD_CLIENT_ID,
            client_credential=AAD_CLIENT_SECRET,
            authority=authority,
        )
    except Exception as e:
        raise RuntimeError(f"MSAL_INIT_ERROR: {e}")

    # Try silent first (usually empty in app-only scenarios, but harmless)
    result: Optional[Dict[str, Any]] = None
    try:
        result = app.acquire_token_silent(scopes=[GRAPH_SCOPE], account=None)
        if not result:
            result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
    except Exception as e:
        raise RuntimeError(f"MSAL_TOKEN_REQUEST_ERROR: {e}")

    if not result:
        raise RuntimeError("MSAL_NO_RESULT: Token result was empty.")

    if "access_token" not in result:
        # Surface MSAL / AAD error details for debugging
        err = result.get("error")
        err_desc = result.get("error_description")
        raise RuntimeError(
            f"MSAL_ERROR: {err or 'unknown'} - {err_desc or 'no description'}"
        )

    return str(result["access_token"])


def _graph_headers(
    token: str, extra: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers


def _graph_get(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """
    Perform a GET request to Microsoft Graph, raising RuntimeError if token acquisition fails.
    """
    token = _get_graph_token()
    url = f"{GRAPH_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = _graph_headers(token, extra_headers)
    resp = requests.get(url, headers=headers, params=params, timeout=10)
    return resp


def _graph_patch(path: str, json_body: Dict[str, Any]) -> requests.Response:
    """
    Perform a PATCH request to Microsoft Graph, raising RuntimeError if token acquisition fails.
    """
    token = _get_graph_token()
    url = f"{GRAPH_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = _graph_headers(token, None)
    resp = requests.patch(url, headers=headers, json=json_body, timeout=10)
    return resp


def _get_identity_context(state: Dict[str, Any]) -> Dict[str, Any]:
    """Helper: safely read identity_context from state."""
    identity = state.get("identity_context") or {}
    if not isinstance(identity, dict):
        identity = {}
    return {
        "display_name": identity.get("display_name"),
        "upn": identity.get("upn") or identity.get("primary_email"),
        "aad_object_id": identity.get("aad_object_id"),
        "department": identity.get("department"),
        "job_title": identity.get("job_title"),
    }


def _norm_host(value: Any) -> Optional[str]:
    """
    Normalize a hostname/device name:
    - lower, strip
    - remove protocol prefix if present
    - remove path/port if present
    - remove trailing dot
    """
    if value is None or not isinstance(value, str):
        return None
    s = value.strip().lower()
    if not s:
        return None

    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[-1]

    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    if s.endswith("."):
        s = s[:-1]
    return s or None


def _extract_hosts_from_graph_devices(devices: List[Dict[str, Any]]) -> List[str]:
    """
    Best-effort extraction of host candidates from Graph device objects.
    Typically displayName is present; sometimes other fields might exist depending on tenant/device type.
    """
    out: Set[str] = set()
    for d in devices or []:
        if not isinstance(d, dict):
            continue

        # Try likely fields
        for key in ("displayName", "deviceName", "dnsHostName", "hostname", "name"):
            if key in d:
                h = _norm_host(d.get(key))
                if h:
                    out.add(h)

    return sorted(out)


# ==============================================================================
# AAD USER LOOKUP
# ==============================================================================

def aad_user_lookup(tool_context: ToolContext, query: str) -> Dict[str, Any]:
    """
    Look up Azure AD user(s) by display name, UPN, or email fragment.

    Behavior:
    - If query looks like a UPN (contains '@'):
        -> GET /users/{query}
    - Else:
        -> GET /users?$filter=startsWith(displayName,'query')
           (You can refine this as needed.)

    Returns:
      {
        "ok": bool,
        "query": "...",
        "matches": [
          {
            "display_name": "...",
            "upn": "...",
            "aad_object_id": "...",
          },
          ...
        ],
        "error": "...optional..."
      }
    """
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    # Starting a new target lookup invalidates manager evidence for any
    # previously resolved target, as well as a diagnosis/authorization that a
    # later bare confirmation might otherwise reuse.
    state[AAD_MANAGER_LOOKUP_STATE_KEY] = None
    state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = None
    state[ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY] = None
    state["account_access_diagnosis"] = None
    state["account_access_offer"] = None

    if not _graph_is_configured():
        return {
            "ok": False,
            "query": query,
            "matches": [],
            "error": (
                "Microsoft Graph is not configured "
                "(AAD_TENANT_ID / AAD_CLIENT_ID / AAD_CLIENT_SECRET missing)."
            ),
        }

    try:
        matches: List[Dict[str, Any]] = []

        # Case 1: treat as direct UPN or user ID
        if "@" in query:
            resp = _graph_get(f"users/{query}")
            if resp.status_code == 200:
                u = resp.json()
                matches.append(
                    {
                        "display_name": u.get("displayName"),
                        "upn": u.get("userPrincipalName") or u.get("mail"),
                        "aad_object_id": u.get("id"),
                    }
                )
        else:
            # Case 2: basic displayName prefix search
            params = {
                "$filter": f"startsWith(displayName,'{query}')",
                "$select": "id,displayName,userPrincipalName,mail",
            }
            resp = _graph_get("users", params=params)
            if resp.status_code == 200:
                data = resp.json()
                for u in data.get("value", []):
                    matches.append(
                        {
                            "display_name": u.get("displayName"),
                            "upn": u.get("userPrincipalName") or u.get("mail"),
                            "aad_object_id": u.get("id"),
                        }
                    )

        return {
            "ok": bool(matches),
            "query": query,
            "matches": matches,
            "error": None if matches else "No users found for the given query.",
        }

    except Exception as e:
        return {
            "ok": False,
            "query": query,
            "matches": [],
            "error": f"Error while querying Microsoft Graph: {e}",
        }


aad_user_lookup = FunctionTool(func=aad_user_lookup)


# ==============================================================================
# AAD GET MANAGER
# ==============================================================================

def aad_get_manager(tool_context: ToolContext, target_upn: str) -> Dict[str, Any]:
    """
    Get the manager of the target user from Azure AD.

    Graph:
      GET /users/{target_upn}/manager

    Returns:
      {
        "ok": bool,
        "target_upn": "...",
        "manager": {
          "display_name": "...",
          "upn": "...",
          "aad_object_id": "..."
        } or None,
        "error": "...optional..."
      }
    """
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    state[AAD_MANAGER_LOOKUP_STATE_KEY] = None

    if not _graph_is_configured():
        return {
            "ok": False,
            "target_upn": target_upn,
            "manager": None,
            "error": (
                "Microsoft Graph is not configured "
                "(AAD_TENANT_ID / AAD_CLIENT_ID / AAD_CLIENT_SECRET missing)."
            ),
        }

    try:
        resp = _graph_get(f"users/{target_upn}/manager")
        if resp.status_code != 200:
            return {
                "ok": False,
                "target_upn": target_upn,
                "manager": None,
                "error": f"Graph returned {resp.status_code}: {resp.text}",
            }

        m = resp.json()
        manager = {
            "display_name": m.get("displayName"),
            "upn": m.get("userPrincipalName") or m.get("mail"),
            "aad_object_id": m.get("id"),
        }

        normalized_target = (target_upn or "").strip().lower()
        normalized_manager = (manager["upn"] or "").strip().lower()
        if not normalized_target or not normalized_manager:
            return {
                "ok": False,
                "target_upn": target_upn,
                "manager": None,
                "error": "Graph manager response did not include a usable UPN.",
            }

        state[AAD_MANAGER_LOOKUP_STATE_KEY] = {
            "target_upn": normalized_target,
            "manager_upn": normalized_manager,
            "source": "microsoft_graph",
        }

        return {
            "ok": True,
            "target_upn": target_upn,
            "manager": manager,
            "error": None,
        }

    except Exception as e:
        return {
            "ok": False,
            "target_upn": target_upn,
            "manager": None,
            "error": f"Error while querying manager from Microsoft Graph: {e}",
        }


aad_get_manager = FunctionTool(func=aad_get_manager)


# ==============================================================================
# AAD GET MY DEVICES / ALLOWED HOSTS
# ==============================================================================

def aad_get_my_devices(tool_context: ToolContext) -> Dict[str, Any]:
    """
    Fetch the current caller's registered devices from Azure AD (Microsoft Graph)
    and derive a list of allowed hostnames for endpoint remediation.

    Graph:
      GET /users/{id-or-upn}/registeredDevices?$select=id,displayName,deviceId,operatingSystem

    Behavior:
    - Reads identity_context from state to find aad_object_id or upn.
    - Writes state["allowed_hosts"] = [...]
      and (if identity_context exists) identity_context["allowed_hosts"] = [...]
    - Returns a simple result with allowed_hosts.

    Notes:
    - This tool does NOT grant authorization by itself; it provides the "allowed hosts"
      list used by policy_tool host_is_authorized checks and by endpoint tools.
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    if not _graph_is_configured():
        return {
            "ok": False,
            "allowed_hosts": [],
            "source": "none",
            "error": (
                "Microsoft Graph is not configured "
                "(AAD_TENANT_ID / AAD_CLIENT_ID / AAD_CLIENT_SECRET missing)."
            ),
        }

    identity = state.get("identity_context") or {}
    if not isinstance(identity, dict):
        identity = {}

    user_id_or_upn = identity.get("aad_object_id") or identity.get("upn") or identity.get("primary_email")
    if not user_id_or_upn:
        return {
            "ok": False,
            "allowed_hosts": [],
            "source": "none",
            "error": "Missing identity context (aad_object_id/upn). Call identity_context_tool first.",
        }

    try:
        params = {
            "$select": "id,displayName,deviceId,operatingSystem",
        }
        resp = _graph_get(f"users/{user_id_or_upn}/registeredDevices", params=params)

        if resp.status_code != 200:
            return {
                "ok": False,
                "allowed_hosts": [],
                "source": "graph.registeredDevices",
                "error": f"Graph returned {resp.status_code}: {resp.text}",
            }

        data = resp.json()
        device_list = data.get("value", []) or []
        if not isinstance(device_list, list):
            device_list = []

        allowed_hosts = _extract_hosts_from_graph_devices(device_list)

        # Write to state for policy/tool enforcement
        state["allowed_hosts"] = allowed_hosts
        if "identity_context" in state and isinstance(state["identity_context"], dict):
            state["identity_context"]["allowed_hosts"] = allowed_hosts

        # Optional debug
        try:
            print("[aad_get_my_devices] user:", user_id_or_upn)
            print("[aad_get_my_devices] devices_count:", len(device_list))
            print("[aad_get_my_devices] allowed_hosts:", allowed_hosts)
        except Exception:
            pass

        return {
            "ok": True,
            "allowed_hosts": allowed_hosts,
            "source": "graph.registeredDevices",
            "error": None,
        }

    except Exception as e:
        return {
            "ok": False,
            "allowed_hosts": [],
            "source": "graph.registeredDevices",
            "error": f"Error while querying Microsoft Graph devices: {e}",
        }


aad_get_my_devices = FunctionTool(func=aad_get_my_devices)


# ==============================================================================
# AAD RESET PASSWORD
# ==============================================================================

def _generate_secure_password(length: int = 16) -> str:
    """
    Generate a strong password that should satisfy typical Azure AD complexity requirements.
    NOTE: This is used only for sending to Graph, not for returning to the user.
    """
    alphabet = string.ascii_letters + string.digits + "@#$%&*+-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def aad_reset_password(
    tool_context: ToolContext,
    target_upn: str,
    mode: str = "force_change_on_next_login",
) -> Dict[str, Any]:
    """
    Reset the password for a target Azure AD user via Microsoft Graph.

    Graph pattern (simplified):
      PATCH /users/{id}
      {
        "passwordProfile": {
          "forceChangePasswordNextSignIn": true/false,
          "password": "<NEW_PASSWORD>"
        }
      }

    IMPORTANT:
    - This tool NEVER returns the new password in chat.
    - Authorization (self vs manager) MUST be enforced via policy (check_list)
      BEFORE calling this tool.
    - Delivery of the new password / reset link must be done via your secure
      enterprise channel (email, SMS, portal, etc.), outside of this chat.
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    caller = _get_identity_context(state)

    if not consume_account_access_authorization(
        tool_context,
        target_upn,
        "aad.reset_password",
        require_identity_verification=True,
    ):
        return {
            "reset": {
                "status": "error",
                "message": (
                    "A fresh, target-bound identity and policy verification is "
                    "required before resetting this password."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                },
                "error": "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED",
            }
        }

    if not _graph_is_configured():
        return {
            "reset": {
                "status": "error",
                "message": (
                    "Microsoft Graph is not configured; I can't reset the password from here. "
                    "Please contact the Service Desk or identity team."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                },
                "error": (
                    "CONFIG_MISSING: AAD_TENANT_ID / AAD_CLIENT_ID / AAD_CLIENT_SECRET."
                ),
            }
        }

    try:
        # 1) Resolve user to get their ID (Graph accepts UPN here as well, but we normalize).
        user_resp = _graph_get(
            f"users/{target_upn}",
            # also fetch mail/otherMails so we can email them
            params={"$select": "id,userPrincipalName,mail,otherMails"},
        )
    except Exception as e:
        # Token acquisition or HTTP failure before we even got a response
        return {
            "reset": {
                "status": "error",
                "message": (
                    "An unexpected error occurred while contacting Microsoft Graph. "
                    "Please contact the Service Desk."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                },
                "error": f"TOKEN_OR_CONNECT_ERROR: {e}",
            }
        }

    if user_resp.status_code != 200:
        return {
            "reset": {
                "status": "error",
                "message": (
                    f"I couldn't find the user '{target_upn}' in Azure AD. "
                    "The password reset was not performed."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                },
                "error": f"Graph returned {user_resp.status_code}: {user_resp.text}",
            }
        }

    try:
        user_obj = user_resp.json()

        # DEBUG – what Graph actually returned for the user
        print("==== [DEBUG] GRAPH USER OBJECT ====")
        print(user_obj)
        print("===================================")

        primary_mail = user_obj.get("mail")
        other_mails = user_obj.get("otherMails") or []

        print(f"[DEBUG] primary_mail (mail): {primary_mail}")
        print(f"[DEBUG] other_mails (otherMails): {other_mails}")

        notify_email = None
        if other_mails:
            notify_email = other_mails[0]
        elif primary_mail:
            notify_email = primary_mail

        print(f"[DEBUG] notify_email selected: {notify_email}")

        user_id = user_obj.get("id") or target_upn

        # 2) Generate a new secure password (NOT returned to the user in chat).
        new_password = _generate_secure_password()

        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": (
                    mode == "force_change_on_next_login"
                ),
                "password": new_password,
            }
        }

        patch_resp = _graph_patch(f"users/{user_id}", json_body=body)

        # 3) Handle Graph response
        if patch_resp.status_code not in (200, 204):
            # Differentiate permission issues (403) from other errors
            if patch_resp.status_code == 403:
                user_msg = (
                    f"I'm unable to reset the password for {target_upn} because "
                    "the automation account in Azure AD does not have enough privileges. "
                    "Please contact the identity / Azure AD team to enable this."
                )
            else:
                user_msg = (
                    f"Something went wrong while trying to reset the password for '{target_upn}'. "
                    "Please contact the Service Desk."
                )

            return {
                "reset": {
                    "status": "error",
                    "message": user_msg,
                    "audit": {
                        "requested_by": caller,
                        "target_upn": target_upn,
                        "mode": mode,
                        "backend": "graph",
                    },
                    "error": (
                        f"Graph returned {patch_resp.status_code}: "
                        f"{patch_resp.text}"
                    ),
                }
            }

        # 4) Success – still do NOT reveal the password in chat.
        #    Try to send an email via the generic email tool.

        # Re-select notification email (kept as-is from your version)
        notify_email = None
        primary_mail = user_obj.get("mail")
        other_mails = user_obj.get("otherMails") or []

        if isinstance(other_mails, list) and other_mails:
            notify_email = other_mails[0]
        elif primary_mail:
            notify_email = primary_mail

        email_result: Dict[str, Any] = {}
        if notify_email:
            try:
                # 👇 CHANGE: include the temporary password in the email body
                email_body = (
                    f"Hello,\n\n"
                    f"Your password for account {target_upn} has been reset by the "
                    f"Service Desk automation.\n\n"
                    f"Temporary password (please keep this confidential): {new_password}\n\n"
                    f"You will be required to change this password at the next sign-in.\n\n"
                    f"If you did not request this change, please contact support immediately.\n"
                )

                email_result = send_email_via_gmail(
                    to_email=notify_email,
                    subject="Your password has been reset",
                    body_text=email_body,
                )
            except Exception as e:
                email_result = {
                    "status": "error",
                    "to": notify_email,
                    "error": str(e),
                }
        else:
            email_result = {
                "status": "not_attempted",
                "to": None,
                "error": "No mail/otherMails found on user object.",
            }

        return {
            "reset": {
                "status": "ok",
                "message": (
                    f"Password reset has been completed for {target_upn}. "
                    "They should receive new credentials or reset instructions "
                    "via the official secure channel."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                    "email_notification": email_result,
                },
                "error": None,
            }
        }

    except Exception as e:
        return {
            "reset": {
                "status": "error",
                "message": (
                    "An unexpected error occurred while attempting to reset the password. "
                    "Please contact the Service Desk."
                ),
                "audit": {
                    "requested_by": caller,
                    "target_upn": target_upn,
                    "mode": mode,
                    "backend": "graph",
                },
                "error": f"{e}",
            }
        }


aad_reset_password = FunctionTool(func=aad_reset_password)


# ==============================================================================
# EXPORT LIST
# ==============================================================================

aad_account_tools = [
    aad_user_lookup,
    aad_get_manager,
    aad_get_my_devices,
    aad_reset_password,
]
