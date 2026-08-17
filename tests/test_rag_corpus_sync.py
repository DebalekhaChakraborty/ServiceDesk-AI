"""Guard against the repo and the RAG corpus drifting apart.

The SOPs in docs/ are the approved knowledge the planner is grounded in, and
they are served to it through a Vertex AI RAG corpus. Nothing about editing a
SOP updates that corpus, so the two drift silently — and a stale corpus does not
fail loudly, it just grounds a flow in superseded guidance.

That is not hypothetical. The performance SOP was edited across six commits
while the corpus kept answering from the copy uploaded three days earlier, so
retrieval returned "RDP User Input Delay > 200 ms" long after the
implementation had moved to RDP TCP RTT and begun stating explicitly that input
delay never qualifies cleanup.

The primary test here is offline: it compares the working tree against the
manifest written by the last successful sync, so an edited-but-unsynced SOP
fails the build with no network or credentials involved.
"""

import hashlib
import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "rag_manifest.json"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_rag_corpus.py"

RESYNC_HINT = (
    "The RAG corpus is serving superseded guidance. Re-sync with:\n"
    "    python scripts/sync_rag_corpus.py --apply"
)


def _manifest() -> dict:
    assert MANIFEST_PATH.is_file(), f"missing {MANIFEST_PATH}"
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_well_formed():
    manifest = _manifest()

    assert manifest["corpus_display_name"] == "Service_Desk"
    assert manifest["gcs_prefix"].startswith("gs://")
    assert isinstance(manifest["documents"], dict)
    assert manifest["documents"], "manifest lists no documents"


def test_every_synced_document_exists():
    for relative_path in _manifest()["documents"]:
        assert (REPO_ROOT / relative_path).is_file(), (
            f"{relative_path} is in the corpus manifest but not in the repo. "
            "Remove it from SYNCED_DOCS and re-sync, or restore the file."
        )


def test_no_synced_document_has_drifted_from_the_corpus():
    """The load-bearing check: edit a SOP without re-syncing and this fails."""
    drifted = []
    for relative_path, recorded in _manifest()["documents"].items():
        path = REPO_ROOT / relative_path
        if path.is_file() and _sha256(path) != recorded:
            drifted.append(relative_path)

    assert not drifted, (
        "These documents changed since they were last indexed, so the corpus "
        f"no longer matches the repo: {', '.join(sorted(drifted))}\n{RESYNC_HINT}"
    )


def test_sync_script_declares_the_same_documents_as_the_manifest():
    """A doc added to the script but never synced would otherwise go unnoticed."""
    source = SYNC_SCRIPT.read_text(encoding="utf-8")
    declared = {
        line.strip().strip('",')
        for line in source.split("SYNCED_DOCS: List[str] = [", 1)[1]
        .split("]", 1)[0]
        .splitlines()
        if line.strip().startswith('"')
    }

    assert declared == set(_manifest()["documents"]), (
        "scripts/sync_rag_corpus.py and docs/rag_manifest.json disagree about "
        f"which documents are synced.\n{RESYNC_HINT}"
    )


def test_every_use_case_has_a_source_document():
    """No article may exist only inside the corpus.

    Four KB articles were direct-uploaded in 2025-2026 with no GCS source and no
    repo copy. Vertex exposes no content API, so the corpus was their only copy
    and one delete_file call would have destroyed the article grounding password
    reset or privileged Windows remediation. They are recovered and synced now;
    this test stops the situation recurring.
    """
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    recovered = set(manifest["recovered_from_corpus"])
    synced = set(manifest["documents"])

    assert recovered, "no recovered-article provenance is recorded"
    assert recovered <= synced, (
        "recovered articles missing from the synced set: "
        f"{', '.join(sorted(recovered - synced))}"
    )
    for relative_path in recovered:
        assert (REPO_ROOT / relative_path).is_file(), (
            f"{relative_path} was recovered from the corpus and is the only "
            "copy outside it; it must stay in the repo."
        )


def test_unverified_reconstructions_are_refused_by_apply():
    """The interlock stays wired even though nothing is currently blocked.

    --apply deletes a corpus entry before re-importing it, so pushing an
    unverified reconstruction would destroy the authoritative copy and replace
    it with a lossy one. UNVERIFIED_RECOVERED is empty in the steady state; the
    guard must survive that so the next recovery is protected.
    """
    source = SYNC_SCRIPT.read_text(encoding="utf-8")

    assert "UNVERIFIED_RECOVERED" in source
    assert "refusing to sync unverified reconstructions" in source
    assert "set(SYNCED_DOCS) & set(UNVERIFIED_RECOVERED)" in source


@pytest.mark.skipif(
    not os.getenv("RAG_LIVE_CHECK"),
    reason="live corpus check; set RAG_LIVE_CHECK=1 with GCP credentials",
)
def test_live_corpus_content_matches_the_repo():
    """Opt-in: verify the indexed source objects really match the working tree.

    The offline test proves the repo matches what we believe we uploaded. This
    one proves the upload actually happened and nothing changed it since.
    """
    import subprocess

    manifest = _manifest()
    prefix = manifest["gcs_prefix"].rstrip("/")
    mismatched = []

    for relative_path in manifest["documents"]:
        name = Path(relative_path).name
        result = subprocess.run(
            ["gcloud", "storage", "cat", f"{prefix}/{name}"],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip(f"cannot read {prefix}/{name}; no credentials?")
        if result.stdout != (REPO_ROOT / relative_path).read_bytes():
            mismatched.append(relative_path)

    assert not mismatched, (
        "The indexed GCS objects differ from the repo: "
        f"{', '.join(sorted(mismatched))}\n{RESYNC_HINT}"
    )
