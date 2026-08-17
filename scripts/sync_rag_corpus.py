#!/usr/bin/env python3
"""Sync repository SOPs into the Vertex AI RAG corpus that serves them.

The repository is the source of truth. The corpus is a serving index built from
it, and the two drift apart silently: a SOP can be edited and committed six
times while the corpus keeps answering from the copy uploaded weeks earlier.
That is not a cosmetic staleness — the SOP is the approved knowledge the planner
is grounded in, so a stale corpus can ground a flow in a rule the system has
since repudiated. This happened: the performance SOP served
"RDP User Input Delay > 200 ms" long after the implementation moved to RDP TCP
RTT and began stating explicitly that input delay never qualifies cleanup.

Usage:
    python scripts/sync_rag_corpus.py --check    # report drift, change nothing
    python scripts/sync_rag_corpus.py --apply    # upload, re-index, update manifest

`--check` is read-only and safe to run anywhere. `--apply` mutates a shared
corpus that the live agent queries, so it is never the default.

The manifest (docs/rag_manifest.json) records the sha256 of each document as
last synced. tests/test_rag_corpus_sync.py compares the working tree against it
with no network access, so editing a SOP without re-syncing fails the build
rather than silently degrading retrieval.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "rag_manifest.json"

CORPUS_DISPLAY_NAME = "Service_Desk"
GCS_PREFIX = (
    "gs://cloud-ai-platform-e62fd391-e8ed-4b33-b3e3-af9f9cde9851/"
    "servicedesk-gcp-vdi-poc"
)

# Documents this repository owns in that corpus. Adding one is a single line;
# files in the corpus that are not listed here are left completely alone.
SYNCED_DOCS: List[str] = [
    "docs/gcp_virtual_desktop_login_demo_sop.md",
    "docs/gcp_virtual_desktop_performance_demo_sop.md",
]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_digests() -> Dict[str, str]:
    digests = {}
    for rel in SYNCED_DOCS:
        path = REPO_ROOT / rel
        if not path.is_file():
            raise SystemExit(f"missing document: {rel}")
        digests[rel] = sha256_of(path)
    return digests


def load_manifest() -> Dict[str, str]:
    if not MANIFEST_PATH.is_file():
        return {}
    try:
        data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    documents = data.get("documents")
    return documents if isinstance(documents, dict) else {}


def write_manifest(digests: Dict[str, str]) -> None:
    MANIFEST_PATH.write_text(
        json.dumps(
            {
                "corpus_display_name": CORPUS_DISPLAY_NAME,
                "gcs_prefix": GCS_PREFIX,
                "note": (
                    "sha256 of each document as last synced into the corpus. "
                    "Regenerate with: python scripts/sync_rag_corpus.py --apply"
                ),
                "documents": dict(sorted(digests.items())),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def report_drift(digests: Dict[str, str], manifest: Dict[str, str]) -> int:
    drifted = [
        rel for rel, digest in digests.items() if manifest.get(rel) != digest
    ]
    for rel in SYNCED_DOCS:
        status = "DRIFTED" if rel in drifted else "in sync"
        print(f"  [{status}] {rel}")
    if drifted:
        print(
            f"\n{len(drifted)} document(s) differ from the last synced copy.\n"
            "The corpus is serving superseded guidance. Re-sync with:\n"
            "    python scripts/sync_rag_corpus.py --apply"
        )
        return 1
    print("\nAll synced documents match the corpus manifest.")
    return 0


def apply_sync(digests: Dict[str, str]) -> int:
    # Imported lazily so --check needs neither the SDK nor credentials.
    import vertexai
    from vertexai import rag

    sys.path.insert(0, str(REPO_ROOT))
    from sd_chat.config import (  # noqa: E402
        DEFAULT_CHUNK_OVERLAP,
        DEFAULT_CHUNK_SIZE,
        LOCATION,
        PROJECT_ID,
    )

    print(f"staging {len(SYNCED_DOCS)} document(s) to {GCS_PREFIX}")
    subprocess.run(
        ["gcloud", "storage", "cp", *[str(REPO_ROOT / r) for r in SYNCED_DOCS],
         f"{GCS_PREFIX}/"],
        check=True,
    )

    vertexai.init(project=PROJECT_ID, location=LOCATION)
    corpus = next(
        (
            c
            for c in rag.list_corpora()
            if c.display_name == CORPUS_DISPLAY_NAME
        ),
        None,
    )
    if corpus is None:
        raise SystemExit(f"corpus not found: {CORPUS_DISPLAY_NAME}")

    owned = {Path(rel).name for rel in SYNCED_DOCS}
    # Vertex has no in-place replace: an import alongside the existing entry
    # would leave both the current and the superseded chunks retrievable. Only
    # entries this repository owns are removed.
    for existing in rag.list_files(corpus.name):
        if existing.display_name in owned:
            print(f"  removing stale index entry: {existing.display_name}")
            rag.delete_file(existing.name)

    response = rag.import_files(
        corpus.name,
        [f"{GCS_PREFIX}/{name}" for name in sorted(owned)],
        transformation_config=rag.TransformationConfig(
            chunking_config=rag.ChunkingConfig(
                chunk_size=DEFAULT_CHUNK_SIZE,
                chunk_overlap=DEFAULT_CHUNK_OVERLAP,
            )
        ),
    )
    imported = getattr(response, "imported_rag_files_count", None)
    failed = getattr(response, "failed_rag_files_count", None) or 0
    print(f"  imported={imported} failed={failed}")
    if failed:
        raise SystemExit("import reported failures; manifest not updated")

    write_manifest(digests)
    print(f"manifest updated: {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="report drift only")
    group.add_argument(
        "--apply", action="store_true", help="upload, re-index, update manifest"
    )
    args = parser.parse_args()

    digests = local_digests()
    if args.check:
        return report_drift(digests, load_manifest())
    return apply_sync(digests)


if __name__ == "__main__":
    raise SystemExit(main())
