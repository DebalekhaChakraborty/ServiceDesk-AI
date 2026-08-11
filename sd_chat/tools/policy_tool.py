from typing import List, Dict, Tuple, Optional
import os, socket, time

from google.adk.tools import ToolContext

try:
    import winrm  # type: ignore
except Exception:
    winrm = None

# ====== Config via environment ======
WINRM_USER = os.getenv("WINRM_USERNAME")
WINRM_PASS = os.getenv("WINRM_PASSWORD")
WINRM_PORT = int(os.getenv("WINRM_PORT", "5986"))  # sensible default
WINRM_TRANSPORT = os.getenv("WINRM_TRANSPORT", "ntlm")
WINRM_CERT_VALIDATE = os.getenv("WINRM_CERT_VALIDATE", "false")

ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY = "temp:account_access_authorization"
AAD_MANAGER_LOOKUP_STATE_KEY = "temp:aad_manager_lookup"
ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY = "account_access_identity_verification"
ACCOUNT_DIAGNOSIS_ACTION_ID = "ad.get_account_status"
ACCOUNT_REMEDIATION_ACTION_IDS = {
    "ad.unlock_account",
    "ad.enable_account",
    "aad.reset_password",
}


def consume_account_access_authorization(
    tool_context: Optional[ToolContext],
    target_upn: str,
    action_id: str,
    require_identity_verification: bool = False,
) -> bool:
    """Consume one exact target/action-bound account authorization grant.

    Account grants are deliberately single-use.  Reading or changing directory
    state therefore requires a fresh policy decision for every protected tool
    invocation; a successful grant cannot be replayed later in the conversation.
    """
    state = tool_context.state if tool_context is not None else None
    if state is None:
        return False

    grant = state.get(ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY)
    authorized = bool(
        isinstance(grant, dict)
        and grant.get("authorized") is True
        and grant.get("policy") == "caller_is_self_or_manager"
        and _norm_upn(str(grant.get("target_upn") or ""))
        == _norm_upn(target_upn)
        and grant.get("action_id") == action_id
    )
    if authorized and require_identity_verification:
        verification = state.get(ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY)
        requester = verification.get("requester") if isinstance(verification, dict) else None
        target = verification.get("target") if isinstance(verification, dict) else None
        manager = verification.get("manager") if isinstance(verification, dict) else None
        verified_at = verification.get("verified_at") if isinstance(verification, dict) else None
        try:
            evidence_age = time.time() - float(verified_at)
        except (TypeError, ValueError):
            evidence_age = 10_000.0
        basis = verification.get("authorization_basis") if isinstance(verification, dict) else None
        caller_matches = bool(
            isinstance(requester, dict)
            and _norm_upn(str(requester.get("upn") or ""))
            == _norm_upn(str(grant.get("caller_upn") or ""))
        )
        target_matches = bool(
            isinstance(target, dict)
            and _norm_upn(str(target.get("upn") or "")) == _norm_upn(target_upn)
        )
        relationship_matches = bool(
            (
                basis == "self"
                and _norm_upn(str(grant.get("caller_upn") or ""))
                == _norm_upn(target_upn)
            )
            or (
                basis == "current_graph_manager"
                and isinstance(manager, dict)
                and _norm_upn(str(manager.get("upn") or ""))
                == _norm_upn(str(grant.get("caller_upn") or ""))
            )
        )
        authorized = bool(
            isinstance(verification, dict)
            and verification.get("verification_id")
            and verification.get("verification_id")
            == grant.get("identity_verification_id")
            and verification.get("policy_action_id") == action_id
            and -30.0 <= evidence_age <= 300.0
            and caller_matches
            and target_matches
            and relationship_matches
            and isinstance(verification.get("requester_devices"), list)
            and isinstance(verification.get("target_devices"), list)
        )

    # An unrelated/mismatched tool cannot use this grant, but must not consume
    # the exact action's authorization before that action gets its one attempt.
    if authorized:
        state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = None
    return authorized


def _endpoint(host: str) -> str:
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}:{WINRM_PORT}/wsman"


def _reachable(host: str) -> bool:
    try:
        with socket.create_connection(
            (host.split("://")[-1].split(":")[0], WINRM_PORT), timeout=3.0
        ):
            return True
    except Exception:
        return False


def _is_windows_via_winrm(host: str) -> Tuple[bool, str]:
    if not winrm or not (WINRM_USER and WINRM_PASS):
        return False, "WinRM probe unavailable (missing module or creds)"
    try:
        session = winrm.Session(
            _endpoint(host),
            auth=(WINRM_USER, WINRM_PASS),
            transport=WINRM_TRANSPORT,
            server_cert_validation="validate"
            if WINRM_CERT_VALIDATE.lower() == "true"
            else "ignore",
        )
        ps = r'''
        try {
          $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
        } catch {
          try { $os = (Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
        }
        if (-not $os) { Write-Output "UNKNOWN"; exit 1 }
        Write-Output $os
        exit 0
        '''
        result = session.run_ps(ps)
        caption = (result.std_out or b"").decode(errors="ignore").strip()
        if result.status_code == 0 and "windows" in caption.lower():
            return True, caption or "Windows"
        return False, caption or "Unknown"
    except Exception as e:
        return False, f"WinRM probe failed: {e}"


def _norm_upn(value: Optional[str]) -> str:
    """
    Normalize a UPN/email for comparison:
    - handle None
    - strip whitespace
    - lower-case
    """
    return (value or "").strip().lower()


def _norm_host(value: Optional[str]) -> str:
    """
    Normalize host for comparison:
    - handle None
    - strip whitespace
    - lower-case
    - strip protocol if present
    - strip trailing dot
    - strip port/path if present
    """
    s = (value or "").strip().lower()
    if not s:
        return ""

    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[-1]

    # Drop any path
    s = s.split("/", 1)[0]
    # Drop any port
    s = s.split(":", 1)[0]
    # Drop trailing dot (fqdn may end with ".")
    if s.endswith("."):
        s = s[:-1]

    return s


def _short_host(host: str) -> str:
    """
    Convert a host to "short name" (left-most label).
    Example:
      ws-123.corp.local -> ws-123
    """
    h = _norm_host(host)
    if not h:
        return ""
    return h.split(".", 1)[0]


def _parse_allowed_hosts_csv(allowed_hosts_csv: Optional[str]) -> List[str]:
    """
    Parse allowed hosts from a comma-separated string.
    Accepts blanks gracefully.
    """
    raw = (allowed_hosts_csv or "").strip()
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def software_is_approved(
    software_name: str,
    approved_software_names_csv: str
) -> bool:
    if not software_name or not approved_software_names_csv:
        return False

    requested = software_name.strip().lower()
    approved = [
        s.strip().lower()
        for s in approved_software_names_csv.split(",")
        if s.strip()
    ]

    return requested in approved


def check_list(
    preconditions: List[str],
    target_host: Optional[str] = "",
    caller_role: Optional[str] = "",
    caller_upn: Optional[str] = "",
    target_upn: Optional[str] = "",
    manager_upn: Optional[str] = "",
    endpoint_os: Optional[str] = "",
    endpoint_reachable: Optional[bool] = None,
    allowed_hosts_csv: Optional[str] = "",  # for host authorization enforcement
    software_name: Optional[str] = "",
    account_action_id: Optional[str] = "",
    plan_can_execute_fully: Optional[bool] = None,
    plan_low_confidence: Optional[bool] = None,
    plan_unmapped_count: Optional[int] = None,
    plan_action_count: Optional[int] = None,
    tool_context: Optional[ToolContext] = None,
    # raw_sop_text: Optional[str] = "" ## TODO: for software approval check, need to configure properly, passing raw full text from sop_retriever or planner causing major malfunction issue
) -> Dict[str, object]:
    """
    Policy / safety gate.

    This version is compatible with Google ADK automatic function calling:
    - Only simple fields (no nested dicts).
    - Returns: { "status": "ok" | "error", "message": str, "details": {...} }

    Preconditions are fail-closed: an unrecognized condition returns an error.
    A successful ``caller_is_self_or_manager`` evaluation records a target-bound,
    action-bound authorization grant for protected AD account tools. Omitting
    ``account_action_id`` grants diagnosis-only access. A remediation grant also
    requires an executable, high-confidence, single-action planner result.
    """
    details: Dict[str, object] = {}
    host = target_host or ""
    account_authorization: Optional[Dict[str, object]] = None

    state = tool_context.state if tool_context is not None else None
    if state is not None:
        # A grant is valid only when this invocation successfully re-establishes
        # the canonical account authorization condition. ADK's State supports
        # assignment but not deletion, so an explicit null revokes old grants.
        state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = None

    # High-level debug of each call
    try:
        print("[policy.check_list] called with preconditions:", preconditions)
        print("[policy.check_list] caller_role:", caller_role)
        print("[policy.check_list] caller_upn:", caller_upn)
        print("[policy.check_list] target_upn:", target_upn)
        print("[policy.check_list] manager_upn:", manager_upn)
        print("[policy.check_list] target_host:", host)
        # Avoid dumping long lists in logs; just show count
        ah = _parse_allowed_hosts_csv(allowed_hosts_csv)
        print("[policy.check_list] allowed_hosts_csv count:", len(ah))
    except Exception:
        pass

    for cond in preconditions or []:

        # ------------------------------------------------------------------
        # Role-based check: caller must be at least L1
        # ------------------------------------------------------------------
        if cond == "caller_is_l1_or_above":
            ok = (caller_role or "").lower() in ("l1", "l2", "l3", "admin")
            details["caller_is_l1_or_above"] = ok
            if not ok:
                return {
                    "status": "error",
                    "message": "Insufficient role privilege",
                    "details": details,
                }

        # ------------------------------------------------------------------
        # Identity-based check: self or manager
        # ------------------------------------------------------------------
        elif cond == "caller_is_self_or_manager":
            cu_raw = caller_upn
            tu_raw = target_upn
            mu_raw = manager_upn

            cu = _norm_upn(cu_raw)
            tu = _norm_upn(tu_raw)
            mu = _norm_upn(mu_raw)

            manager_lookup = (
                state.get(AAD_MANAGER_LOOKUP_STATE_KEY) if state is not None else None
            )
            manager_lookup_verified = bool(
                isinstance(manager_lookup, dict)
                and _norm_upn(str(manager_lookup.get("target_upn") or "")) == tu
                and _norm_upn(str(manager_lookup.get("manager_upn") or "")) == mu
            )
            caller_is_self = bool(cu and cu == tu)
            caller_is_verified_manager = bool(
                cu and mu and cu == mu and manager_lookup_verified
            )
            ok = caller_is_self or caller_is_verified_manager

            # Add rich debug info so we can see what was compared
            details["caller_is_self_or_manager"] = {
                "ok": ok,
                "caller_upn": cu_raw,
                "target_upn": tu_raw,
                "manager_upn": mu_raw,
                "manager_lookup_verified": manager_lookup_verified,
                "normalized": {
                    "caller": cu,
                    "target": tu,
                    "manager": mu,
                },
            }

            # Console debug so you can see actual AD values in logs
            # try:
            print("[policy.check_list] caller_is_self_or_manager inputs:")
            print("  caller_upn (raw):   ", cu_raw)
            print("  target_upn (raw):   ", tu_raw)
            print("  manager_upn (raw):  ", mu_raw)
            print("  normalized caller:  ", cu)
            print("  normalized target:  ", tu)
            print("  normalized manager: ", mu)
            print("  manager lookup verified:", manager_lookup_verified)
            print("  authorized?         ", ok)
            # except Exception:
            #     pass

            if not ok:
                return {
                    "status": "error",
                    "message": "User not authorized to act on this account",
                    "details": details,
                }

            account_authorization = {
                "authorized": True,
                "caller_upn": cu,
                "target_upn": tu,
                "manager_upn": mu,
                "policy": "caller_is_self_or_manager",
                "action_id": ACCOUNT_DIAGNOSIS_ACTION_ID,
            }

            requested_action_id = (account_action_id or "").strip()
            if requested_action_id:
                plan_safe = bool(
                    requested_action_id in ACCOUNT_REMEDIATION_ACTION_IDS
                    and plan_can_execute_fully is True
                    and plan_low_confidence is False
                    and plan_unmapped_count == 0
                    and plan_action_count == 1
                )
                details["account_remediation_plan"] = {
                    "ok": plan_safe,
                    "action_id": requested_action_id,
                    "can_execute_fully": plan_can_execute_fully,
                    "low_confidence": plan_low_confidence,
                    "unmapped_count": plan_unmapped_count,
                    "action_count": plan_action_count,
                }
                if not plan_safe:
                    return {
                        "status": "error",
                        "code": "ACCOUNT_PLAN_NOT_EXECUTABLE",
                        "message": (
                            "Account remediation requires one fully mapped, "
                            "high-confidence expected action."
                        ),
                        "details": details,
                    }
                account_authorization["action_id"] = requested_action_id

        # ------------------------------------------------------------------
        # Host authorization (NEW): target_host must be in allowed hosts list
        # ------------------------------------------------------------------
        elif cond == "host_is_authorized":
            allowed_hosts = _parse_allowed_hosts_csv(allowed_hosts_csv)

            # Normalize for comparison (support short-name vs FQDN match)
            target_norm = _norm_host(host)
            target_short = _short_host(host)

            allowed_norm = [_norm_host(h) for h in allowed_hosts]
            allowed_short = [_short_host(h) for h in allowed_hosts]

            ok = False
            if target_norm:
                # Exact match on normalized host OR shortname match
                ok = (target_norm in allowed_norm) or (target_short and target_short in allowed_short)

            details["host_is_authorized"] = {
                "ok": ok,
                "target_host": host,
                "normalized": {
                    "target": target_norm,
                    "target_short": target_short,
                },
                "allowed_hosts_count": len(allowed_hosts),
            }

            # Helpful debug line (but not dumping full list)
            try:
                print("[policy.check_list] host_is_authorized:")
                print("  target_host:", host)
                print("  target_norm:", target_norm)
                print("  target_short:", target_short)
                print("  allowed_hosts_count:", len(allowed_hosts))
                print("  authorized? ", ok)
            except Exception:
                pass

            if not ok:
                return {
                    "status": "error",
                    "message": (
                        "Target host is not authorized for this user. "
                        "Please choose a device from your allowed device list."
                    ),
                    "details": details,
                }

        # ------------------------------------------------------------------
        # Endpoint reachability
        # ------------------------------------------------------------------
        elif cond == "endpoint_reachable":
            if endpoint_reachable is None:
                details["endpoint_reachable"] = _reachable(host)
            else:
                details["endpoint_reachable"] = bool(endpoint_reachable)

            if not details["endpoint_reachable"]:
                return {
                    "status": "error",
                    "message": f"Target not reachable on port {WINRM_PORT}: {host}",
                    "details": details,
                }

        # ------------------------------------------------------------------
        # Endpoint OS check
        # ------------------------------------------------------------------
        elif cond == "endpoint_is_windows":
            if endpoint_os:
                ok = endpoint_os.lower() == "windows"
                details["endpoint_is_windows"] = ok
                details["endpoint_os_caption"] = endpoint_os
            else:
                ok, caption = _is_windows_via_winrm(host)
                details["endpoint_is_windows"] = ok
                details["endpoint_os_caption"] = caption

            if not details.get("endpoint_is_windows"):
                return {
                    "status": "error",
                    "message": f"{host} is not a Windows system",
                    "details": details,
                }

        # ------------------------------------------------------------------
        # Sofware approval check
        # ------------------------------------------------------------------
        elif cond == "software_is_approved":
            ## TODO: for software approval check, need to configure properly, 
            # passing raw full text from sop_retriever or planner causing major malfunction issue
            approved_software_names_csv = "7-Zip,Google Chrome,Notepad++,7-zip,7zip" 
            
            name = (software_name or "").strip()
            approved_csv = approved_software_names_csv or ""

            details["software_is_approved"] = {
                "requested_software": name,
                "approved_list": approved_csv,
            }

            if not software_is_approved(name, approved_csv):
                return {
                    "status": "error",
                    "message": (
                        f"Requested software '{name}' is not approved "
                        "for automated installation."
                    ),
                    "details": {
                        **details,
                        "policy": "software_is_approved",
                    },
                }


        # ------------------------------------------------------------------
        # Unknown preconditions must fail closed. A generated or paraphrased
        # policy name must never bypass a real authorization check.
        # ------------------------------------------------------------------
        else:
            details[cond] = {
                "ok": False,
                "error": "unknown_precondition",
            }
            return {
                "status": "error",
                "code": "UNKNOWN_PRECONDITION",
                "message": f"Unsupported policy precondition: {cond}",
                "details": details,
            }

    if state is not None and account_authorization is not None:
        state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = account_authorization

    return {"status": "ok", "details": details}
