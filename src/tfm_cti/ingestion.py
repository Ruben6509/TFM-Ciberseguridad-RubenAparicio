from __future__ import annotations

from typing import Any
from haystack_integrations.document_stores.chroma import ChromaDocumentStore

from .settings import resolve


# Apertura del índice Chroma
def open_document_store(config: dict[str, Any]) -> ChromaDocumentStore:
    index = config["index"]
    return ChromaDocumentStore(
        collection_name=index["collection_name"],
        persist_path=str(resolve(index["chroma_path"])),
        distance_function=index["distance_function"],
    )
