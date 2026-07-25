"""
Utility functions for the RAG tools.
"""

import logging
import re

from google.adk.tools.tool_context import ToolContext
from vertexai import rag

from ..config import (
    LOCATION,
    PROJECT_ID,
)

logger = logging.getLogger(__name__)


def get_corpus_resource_name(corpus_name: str) -> str:
    """
    Convert a corpus name to its full resource name if needed.
    Handles various input formats and ensures the returned name follows Vertex AI's requirements.

    Args:
        corpus_name (str): Service_Desk

    Returns:
        str: The full resource name of the corpus
    """
    logger.info(f"Getting resource name for corpus: {corpus_name}")

    # If it's already a full resource name with the projects/locations/ragCorpora format
    if re.match(r"^projects/[^/]+/locations/[^/]+/ragCorpora/[^/]+$", corpus_name):
        return corpus_name

    # Check if this is a display name of an existing corpus
    try:
        # List all corpora and check if there's a match with the display name
        corpora = rag.list_corpora()
        for corpus in corpora:
            if hasattr(corpus, "display_name") and corpus.display_name == corpus_name:
                return corpus.name
    except Exception as e:
        logger.warning(f"Error when checking for corpus display name: {str(e)}")
        # If we can't check, continue with the default behavior
        pass

    # If it contains partial path elements, extract just the corpus ID
    if "/" in corpus_name:
        # Extract the last part of the path as the corpus ID
        corpus_id = corpus_name.split("/")[-1]
    else:
        corpus_id = corpus_name

    # Remove any special characters that might cause issues
    corpus_id = re.sub(r"[^a-zA-Z0-9_-]", "_", corpus_id)

    # Construct the standardized resource name
    return f"projects/{PROJECT_ID}/locations/{LOCATION}/ragCorpora/{corpus_id}"


def check_corpus_exists(corpus_name: str, tool_context: ToolContext) -> bool:
    """
    Check if a corpus with the given name exists.

    Args:
        corpus_name (str): Service_Desk
        tool_context (ToolContext): The tool context for state management

    Returns:
        bool: True if the corpus exists, False otherwise
    """
    # Check state first if tool_context is provided
    if tool_context.state.get(f"corpus_exists_{corpus_name}"):
        return True

    try:
        # Get full resource name
        corpus_resource_name = get_corpus_resource_name(corpus_name)

        # List all corpora and check if this one exists
        corpora = rag.list_corpora()
        for corpus in corpora:
            if (
                corpus.name == corpus_resource_name
                or corpus.display_name == corpus_name
            ):
                # Update state
                tool_context.state[f"corpus_exists_{corpus_name}"] = True
                # Also set this as the current corpus if no current corpus is set
                if not tool_context.state.get("current_corpus"):
                    tool_context.state["current_corpus"] = corpus_name
                return True

        return False
    except Exception as e:
        logger.error(f"Error checking if corpus exists: {str(e)}")
        # If we can't check, assume it doesn't exist
        return False


def set_current_corpus(corpus_name: str, tool_context: ToolContext) -> bool:
    """
    Set the current corpus in the tool context state.

    Args:
        corpus_name (str): Service_Desk
        tool_context (ToolContext): The tool context for state management

    Returns:
        bool: True if the corpus exists and was set as current, False otherwise
    """
    # Check if corpus exists first
    if check_corpus_exists(corpus_name, tool_context):
        tool_context.state["current_corpus"] = corpus_name
        return True
    return False


#----------------------------------------------------------------------------- #
# Email Setup with Gmail #
#----------------------------------------------------------------------------- #

"""
Utility functions for Gmail integration (send-only).

This mirrors the pattern used in calendar_utils.py from your voice agent:
- credentials.json at repo root
- token cached under ~/.credentials
"""

import json
import os
from pathlib import Path

from google.auth.transport.requests import Request  # type: ignore
from google.oauth2.credentials import Credentials  # type: ignore
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore
from googleapiclient.discovery import build  # type: ignore

# Scope just for sending email
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Token + credentials paths (same style as calendar_utils)
TOKEN_PATH = Path(os.path.expanduser("~/.credentials/gmail_token.json"))
CREDENTIALS_PATH = Path("credentials.json")


def get_gmail_service():
    """
    Authenticate and create a Gmail service object.

    Reuses the same pattern as get_calendar_service():
    - If TOKEN_PATH exists, load creds from there
    - If expired, refresh
    - Else, start InstalledAppFlow using credentials.json
    - Save token for next time
    """
    creds = None

    # 1) Try existing token
    if TOKEN_PATH.exists():
        try:
            data = json.loads(TOKEN_PATH.read_text())
            creds = Credentials.from_authorized_user_info(data, SCOPES)
        except Exception as e:
            print(f"[gmail_utils] Failed to load token from {TOKEN_PATH}: {e}")
            creds = None

    # 2) Refresh or run OAuth flow if needed
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"[gmail_utils] Failed to refresh Gmail token: {e}")
                creds = None

        if not creds or not creds.valid:
            # Fall back to interactive flow (usually one-time in dev)
            if not CREDENTIALS_PATH.exists():
                print(
                    f"[gmail_utils] Error: {CREDENTIALS_PATH} not found. "
                    "Please place your OAuth client JSON here."
                )
                return None

            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_PATH,
                SCOPES,
            )
            creds = flow.run_local_server(port=0)

        # 3) Save token for future runs
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(creds.to_json())

    # 4) Build and return Gmail service
    return build("gmail", "v1", credentials=creds)
