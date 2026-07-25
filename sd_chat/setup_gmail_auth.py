#!/usr/bin/env python3
"""
Gmail Authentication Setup Script

This script helps you set up OAuth 2.0 credentials for Gmail integration
(e.g., sending emails from your agent using the Gmail API).

Follow the instructions in the console.
"""

import os
from pathlib import Path
import base64
from email.message import EmailMessage

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# -----------------------------------------------------------------------------
# SCOPES:
#   - "gmail.send" is enough for sending email only (no read access).
#   - If you later want more (read, list, etc.), you can expand this.
# -----------------------------------------------------------------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Path for token storage
TOKEN_PATH = Path(os.path.expanduser("~/.credentials/gmail_token.json"))

# OAuth client JSON:
# - You can reuse the SAME credentials.json you used for Calendar
#   (just ensure Gmail API is enabled in the same GCP project).
CREDENTIALS_PATH = Path("credentials.json")  # or "gmail_credentials.json" if you prefer


def setup_oauth():
    """Set up OAuth 2.0 for Gmail (send email)."""
    print("\n=== Gmail OAuth Setup ===\n")

    if not CREDENTIALS_PATH.exists():
        print(f"Error: {CREDENTIALS_PATH} not found!")
        print("\nTo set up Gmail integration:")
        print("1. Go to https://console.cloud.google.com/")
        print("2. Select the same project you used for Calendar (recommended)")
        print("3. Enable the Gmail API")
        print("4. Create OAuth 2.0 credentials (Desktop application)")
        print("5. Download the credentials and save them as "
              f"'{CREDENTIALS_PATH.name}' in this directory")
        print("\nThen run this script again.")
        return False

    print(f"Found {CREDENTIALS_PATH.name}. Setting up OAuth flow...")

    try:
        # Run the OAuth flow
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
        creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(creds.to_json())

        print(f"\nSuccessfully saved Gmail credentials to {TOKEN_PATH}")

        # ---------------------------------------------------------------------
        # ✅ New test: send a tiny test email (optional) instead of listing labels
        # ---------------------------------------------------------------------
        print("\nTesting connection to Gmail API by sending a test email (optional)...")

        service = build("gmail", "v1", credentials=creds)

        # You can set this in your environment before running:
        #   export GMAIL_TEST_RECIPIENT="your.personal@gmail.com"
        test_recipient = os.getenv("GMAIL_TEST_RECIPIENT")

        if not test_recipient:
            print(
                "Skipping test send: set GMAIL_TEST_RECIPIENT in your environment "
                "if you want to receive a test email."
            )
        else:
            try:
                msg = EmailMessage()
                msg["To"] = test_recipient
                msg["Subject"] = "ADK Gmail setup test"
                msg.set_content(
                    "This is a test email from the ADK Gmail OAuth setup script.\n"
                    "If you received this, Gmail API (send) is working."
                )

                raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

                service.users().messages().send(
                    userId="me",
                    body={"raw": raw},
                ).execute()

                print(f"Test email sent successfully to {test_recipient}.")

            except Exception as e:
                print(f"Error during test send: {e}")

        print(
            "\nGmail OAuth setup complete! You can now use the Gmail API "
            "for sending emails from your agent."
        )
        return True

    except Exception as e:
        print(f"\nError during setup: {str(e)}")
        return False


if __name__ == "__main__":
    setup_oauth()
