from __future__ import annotations

import re
import sqlite3
import time
import torch
from typing import Any
import os
from haystack import Pipeline, component
from haystack_integrations.components.retrievers.chroma import ChromaEmbeddingRetriever
from sentence_transformers import SentenceTransformer

from .ingestion import open_document_store
from .settings import load_config, read_json, resolve, sha256_text


# Modelo de embeddings para las consultas
@component
class LocalQueryEmbedder:
    def __init__(self, model_reference: str, local_only: bool = False) -> None:
        device = "cuda:0" if torch.cuda.is_available() else "cpu"
        self.model = SentenceTransformer(
            model_reference, device=device, trust_remote_code=True, local_files_only=local_only,
            model_kwargs={"dtype": torch.float16} if torch.cuda.is_available() else {},
        )

    @component.output_types(embedding=list[float])
    def run(self, text: str) -> dict[str, list[float]]:
        vector = self.model.encode(
            text, prompt_name="query", normalize_embeddings=True,
            convert_to_numpy=True, show_progress_bar=False,
        )
        return {"embedding": vector.tolist()}


# Recuperación local
class LocalRetriever:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or load_config()
        self.store = open_document_store(self.config)
        self.pipeline: Pipeline | None = None
        self.chunk_tokens = read_json(resolve(self.config["index"]["token_counts"]))

    # Búsqueda semántica con Haystack y Chroma
    def _semantic_pipeline(self) -> Pipeline:
        if self.pipeline is None:
            embedding = self.config["embedding"]
            reference = os.environ.get("TFM_EMBEDDING_MODEL", embedding["model"])
            candidate = resolve(reference)
            if candidate.exists():
                reference = str(candidate)
            self.pipeline = Pipeline()
            self.pipeline.add_component(
                "embedder", LocalQueryEmbedder(reference, bool(embedding.get("local_only", False)))
            )
            self.pipeline.add_component(
                "retriever", ChromaEmbeddingRetriever(
                    self.store, top_k=self.config["retrieval"]["top_k"]
                )
            )
            self.pipeline.connect("embedder.embedding", "retriever.query_embedding")
        return self.pipeline

    # Consulta exacta de CVE en SQLite
    def _exact_cve(self, query: str) -> dict[str, Any]:
        match = re.search(r"CVE-\d{4}-\d{4,}", query, flags=re.IGNORECASE)
        if not match:
            raise ValueError("La ruta cve_exact exige un identificador CVE")
        requested = match.group(0).upper()
        with sqlite3.connect(resolve(self.config["index"]["exact_cve_sqlite"])) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM cve_records WHERE cve_id = ?", (requested,)).fetchone()
        return {
            "requested_cve_id": requested,
            "found": row is not None,
            "record": dict(row) if row else None,
            "snapshot": self.config["index"]["cve_snapshot"],
        }

    # Selección de la ruta y recuperación
    def retrieve(self, route: str, query: str) -> dict[str, Any]:
        started = time.perf_counter()
        base = {"route": route, "query": query, "query_sha256": sha256_text(query)}
        if route == "none":
            return {**base, "documents": [], "exact": None, "elapsed_seconds": time.perf_counter() - started}
        if route == "cve_exact":
            return {**base, "documents": [], "exact": self._exact_cve(query), "elapsed_seconds": time.perf_counter() - started}
        collection = self.config["retrieval"]["semantic_routes"].get(route)
        if collection is None:
            raise ValueError(f"Ruta desconocida: {route}")
        output = self._semantic_pipeline().run({
            "embedder": {"text": query},
            "retriever": {
                "filters": {"field": "meta.collection", "operator": "==", "value": collection},
                "top_k": self.config["retrieval"]["top_k"],
            },
        })
        documents = output["retriever"]["documents"]
        ranking = [
            {
                "rank": rank, "score": doc.score, "chunk_id": doc.id, "content": doc.content,
                "collection": doc.meta["collection"], "source_record_id": doc.meta["source_record_id"],
                "canonical_document_id": doc.meta["canonical_document_id"],
                "content_start": doc.meta["content_start"], "content_end": doc.meta["content_end"],
                "chunk_text_sha256": doc.meta["chunk_text_sha256"],
                "source_url": doc.meta["source_url"], "source_version": doc.meta["source_version"],
                "token_count": int(self.chunk_tokens[doc.id]),
            }
            for rank, doc in enumerate(documents, 1)
        ]
        return {**base, "documents": ranking, "exact": None, "elapsed_seconds": time.perf_counter() - started}
