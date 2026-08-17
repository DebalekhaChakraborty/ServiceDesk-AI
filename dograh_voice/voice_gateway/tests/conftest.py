import sys
from pathlib import Path

import pytest

# Make `voice_gateway` importable without adding an __init__.py to dograh_voice/
# (which would make ADK treat it as an agent package).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(autouse=True)
def _isolate_runtime(monkeypatch, tmp_path_factory):
    """No test may reach a live Duo tenant or touch the real identity map.

    `create_app()` builds the recovery provider from `dograh_voice/runtime/`
    when one is not injected, so the moment real credentials exist on that
    host every test that constructs an app signs a request to the live Duo
    tenant and creates the real `recovery_identity.db` as a side effect. That
    is slow, it is a dependency on someone else's uptime, and — since the same
    integration key serves real employees — it is not something a test run
    should be doing at all.

    Both secret directories are redirected at an empty sandbox and every
    credential variable is cleared, so the suite behaves identically whether
    or not the host is provisioned. A test that wants configured credentials
    sets its own; monkeypatch inside the test body wins over this fixture.
    """
    sandbox = tmp_path_factory.mktemp("runtime")
    monkeypatch.setattr("voice_gateway.duo_provider.RUNTIME", sandbox)
    monkeypatch.setattr("voice_gateway.graph_corroboration.RUNTIME", sandbox)
    monkeypatch.setattr("voice_gateway.identity_map.RUNTIME", sandbox)
    for name in (
        "DUO_IKEY", "DUO_SKEY", "DUO_HOST", "DUO_SIGNATURE_ALGORITHM",
        "RECOVERY_GRAPH_TENANT_ID", "RECOVERY_GRAPH_CLIENT_ID",
        "RECOVERY_GRAPH_CLIENT_SECRET", "RECOVERY_DEFAULT_CALLING_CODE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("RECOVERY_IDENTITY_DB", str(sandbox / "identity.db"))
    return sandbox
