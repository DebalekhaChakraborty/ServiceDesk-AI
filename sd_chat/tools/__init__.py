"""
RAG Tools package for interacting with Vertex AI RAG corpora.
"""

from .vertex_rag_tool import vertex_rag_tool

from .utils import (
    check_corpus_exists,
    get_corpus_resource_name,
    set_current_corpus,
)

__all__ = [
    "vertex_rag_tool",
    "check_corpus_exists",
    "get_corpus_resource_name",
    "set_current_corpus"
]
