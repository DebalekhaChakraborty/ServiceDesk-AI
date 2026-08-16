import sys
from pathlib import Path

# Make `voice_gateway` importable without adding an __init__.py to dograh_voice/
# (which would make ADK treat it as an agent package).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
