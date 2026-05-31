from __future__ import annotations

import json
from pathlib import Path

from .corpus import default_standards_corpus_root, load_standard_corpus
from .schemas import RagChunk


DEFAULT_INDEX_PATH = Path(__file__).resolve().parents[2] / "data" / "rag_index.json"


def build_rag_index(
    *,
    corpus_root: str | Path | None = None,
    index_path: str | Path | None = None,
) -> list[RagChunk]:
    chunks = load_standard_corpus(corpus_root)
    if index_path is not None:
        output_path = Path(index_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps([_chunk_to_dict(chunk) for chunk in chunks], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return chunks


def load_rag_index(
    *,
    corpus_root: str | Path | None = None,
    index_path: str | Path | None = None,
) -> list[RagChunk]:
    path = Path(index_path) if index_path is not None else DEFAULT_INDEX_PATH
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return [_dict_to_chunk(item) for item in data]
    return build_rag_index(corpus_root=corpus_root, index_path=path)


def _chunk_to_dict(chunk: RagChunk) -> dict[str, object]:
    return {
        "chunk_id": chunk.chunk_id,
        "source_path": chunk.source_path,
        "framework": chunk.framework,
        "section": chunk.section,
        "chunk_text": chunk.chunk_text,
        "tags": chunk.tags,
        "priority": chunk.priority,
    }


def _dict_to_chunk(value: dict[str, object]) -> RagChunk:
    return RagChunk(
        chunk_id=str(value.get("chunk_id") or ""),
        source_path=str(value.get("source_path") or ""),
        framework=str(value.get("framework") or ""),
        section=str(value.get("section") or ""),
        chunk_text=str(value.get("chunk_text") or ""),
        tags=[str(item) for item in value.get("tags", []) if str(item).strip()],
        priority=int(value.get("priority") or 0),
    )
