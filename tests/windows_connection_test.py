import winrm

HOST = "windows-instance.us-central1-a.c.ai-and-automation-coe.internal"
USER = r"WINDOWS-INSTANC\winrm_user"   # or r".\winrm_user"
PASS = "FERLWjfrqg31540!-+#&"

session = winrm.Session(
    f"https://{HOST}:5986/wsman",
    auth=(USER, PASS),
    transport="ntlm",
    server_cert_validation="ignore"   # ok for self-signed in lab
)
r = session.run_cmd("hostname")
print(r.status_code, r.std_out.decode(), r.std_err.decode())
