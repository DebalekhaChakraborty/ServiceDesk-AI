import os
import winrm

HOST = os.getenv("WINRM_HOST", "windows-instance.us-central1-a.c.ai-and-automation-coe.internal")
USER = os.getenv("WINRM_USERNAME", r".\winrm_user")
PASS = os.getenv("WINRM_PASSWORD", "")

if not PASS:
    print("Skipping manual live test: WINRM_PASSWORD not set")
    exit(0)

session = winrm.Session(
    f"https://{HOST}:5986/wsman",
    auth=(USER, PASS),
    transport=os.getenv("WINRM_TRANSPORT", "ntlm"),
    server_cert_validation=os.getenv("WINRM_CERT_VALIDATE", "ignore")
)
try:
    r = session.run_cmd("hostname")
    print(r.status_code, r.std_out.decode(), r.std_err.decode())
except Exception as e:
    print("Connection failed:", str(e))
