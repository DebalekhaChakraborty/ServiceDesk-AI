from typing import Dict, Any
import os
import base64
from email.message import EmailMessage

from google.adk.tools import FunctionTool, ToolContext  # type: ignore

from .utils import get_gmail_service

# Sender address – must match the account you authorized
# Example in .env: GMAIL_SENDER="yourname@gmail.com"
GMAIL_SENDER = os.getenv("GMAIL_SENDER")


# ---------------------------------------------------------------------------
# Low-level reusable helper (for Python code: AD password reset, etc.)
# ---------------------------------------------------------------------------

def send_email_via_gmail(
    to_email: str,
    subject: str,
    body_text: str,
) -> Dict[str, Any]:
    """
    Send a plain-text email using Gmail API.

    This is reusable from *any* Python code:
      - AD password reset flow
      - Future tools (alerts, SOP emails, etc.)
    """
    if not GMAIL_SENDER:
        return {
            "status": "error",
            "to": to_email,
            "error": "GMAIL_SENDER is not configured in environment.",
        }

    service = get_gmail_service()
    if service is None:
        return {
            "status": "error",
            "to": to_email,
            "error": "Gmail service could not be initialized (check token/credentials).",
        }

    try:
        msg = EmailMessage()
        msg["To"] = to_email
        msg["From"] = GMAIL_SENDER
        msg["Subject"] = subject
        msg.set_content(body_text)

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

        service.users().messages().send(
            userId="me",
            body={"raw": raw},
        ).execute()

        return {
            "status": "ok",
            "to": to_email,
            "error": None,
        }

    except Exception as e:
        return {
            "status": "error",
            "to": to_email,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# ADK FunctionTool wrapper (for LLM / agent usage)
# ---------------------------------------------------------------------------

def gmail_send_email_impl(
    tool_context: ToolContext,
    to_email: str,
    subject: str,
    body_text: str,
) -> Dict[str, Any]:
    """
    Tool wrapper around send_email_via_gmail.

    The LLM can call this tool directly in any flow:
    - Incident updates
    - SOP shares
    - Password reset notifications (if you want LLM-driven)
    """
    # You can inspect tool_context.state here if you ever want to
    # personalize or audit more details.

    return send_email_via_gmail(
        to_email=to_email,
        subject=subject,
        body_text=body_text,
    )


gmail_send_email = FunctionTool(func=gmail_send_email_impl)
