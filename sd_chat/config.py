import os
import json
from dotenv import load_dotenv

load_dotenv()

# Vertex AI settings
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT")
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION")

# RAG settings
DEFAULT_CHUNK_SIZE = 512
DEFAULT_CHUNK_OVERLAP = 100
DEFAULT_TOP_K = 3
DEFAULT_DISTANCE_THRESHOLD = 0.5
DEFAULT_EMBEDDING_MODEL = "publishers/google/models/text-embedding-005"
DEFAULT_EMBEDDING_REQUESTS_PER_MIN = 1000


# Tool Context for User Identity

DEV_MODE = os.environ.get("DEV_MODE", "false").lower() == "true"
_DEV_PERSONA_RAW = os.environ.get("DEV_DEFAULT_PERSONA_JSON", "")


import json
import os
from typing import Any, Dict, Optional

def get_env_fallback_persona() -> Optional[Dict[str, Any]]:
    """
    Returns a persona dict from DEV_DEFAULT_PERSONA_JSON if configured and valid.
    Used as a fallback when no persona is provided by the frontend.
    """
    raw = os.environ.get("DEV_DEFAULT_PERSONA_JSON", "").strip()
    if not raw:
        return None

    try:
        persona = json.loads(raw)
        if isinstance(persona, dict):
            return persona
        print("[config] DEV_DEFAULT_PERSONA_JSON is not a JSON object; ignoring.")
        return None
    except Exception as e:
        print("[config] DEV_DEFAULT_PERSONA_JSON is not valid JSON; ignoring.", e)
        return None

