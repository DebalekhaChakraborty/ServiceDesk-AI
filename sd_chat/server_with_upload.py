import os
import uuid
import uvicorn
from fastapi import UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from google.adk.cli.fast_api import get_fast_api_app

# ✅ Load .env from THIS folder
try:
    from dotenv import load_dotenv  # type: ignore

    HERE = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(HERE, ".env"))
    print("[server] Loaded .env from:", os.path.join(HERE, ".env"))
except Exception as e:
    print("[server] dotenv not loaded (ok if env already set):", e)

# --------------------------------------------------------------------------------------
# 1) Build the ADK FastAPI app
# --------------------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS_DIR = os.getenv("ADK_AGENTS_DIR") or os.path.abspath(os.path.join(HERE, ".."))

app = get_fast_api_app(
    agents_dir=AGENTS_DIR,
    web=False,
)

# --------------------------------------------------------------------------------------
# 2) Upload directory (Service Desk)
# --------------------------------------------------------------------------------------
ATTACHMENT_FILE_DIR = os.getenv("ATTACHMENT_FILE_DIR") or os.path.join(HERE, "attachment_files")
UPLOAD_DIR = os.path.join(ATTACHMENT_FILE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

print("[server] FILE =", __file__)
print("[server] CWD =", os.getcwd())
print("[server] AGENTS_DIR =", AGENTS_DIR)
print("[server] ATTACHMENT_FILE_DIR =", ATTACHMENT_FILE_DIR)
print("[server] UPLOAD_DIR =", UPLOAD_DIR)

# --------------------------------------------------------------------------------------
# 3) Upload endpoint (keep same pattern as Ticket QA)
# --------------------------------------------------------------------------------------
@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    """
    Upload an attachment (image) for screenshot-driven troubleshooting.

    Returns:
      {
        ok: true,
        originalName: "...",
        filename: "...",
        filePath: "...",   # absolute path on backend
        size: 12345
      }
    """
    try:
        # Allow common screenshot extensions; otherwise keep original ext if present
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".webp"):
            raise HTTPException(status_code=400, detail="Unsupported file type. Upload PNG/JPG/WEBP.")

        safe = f"{uuid.uuid4().hex}{ext}"
        file_path = os.path.join(UPLOAD_DIR, safe)

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        return {
            "ok": True,
            "originalName": file.filename,
            "filename": safe,
            "filePath": file_path,  # absolute path on backend
            "size": len(content),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --------------------------------------------------------------------------------------
# 4) Download endpoint (optional, useful for debugging / portal preview)
# --------------------------------------------------------------------------------------
@app.get("/api/download")
async def download(filename: str):
    try:
        filename = os.path.basename(filename)  # security

        candidates = [
            os.path.join(UPLOAD_DIR, filename),
            os.path.join(ATTACHMENT_FILE_DIR, filename),
            os.path.join(HERE, filename),
        ]

        file_path = next((p for p in candidates if os.path.isfile(p)), None)

        if not file_path:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "File not found",
                    "filename": filename,
                    "debug": {
                        "cwd": os.getcwd(),
                        "AGENTS_DIR": AGENTS_DIR,
                        "ATTACHMENT_FILE_DIR": ATTACHMENT_FILE_DIR,
                        "UPLOAD_DIR": UPLOAD_DIR,
                        "searched": candidates,
                        "listing_uploads": os.listdir(UPLOAD_DIR) if os.path.isdir(UPLOAD_DIR) else "missing",
                    },
                },
            )

        # media type: generic binary; caller can infer from extension
        return FileResponse(file_path, filename=filename)

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --------------------------------------------------------------------------------------
# 5) Run
# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
