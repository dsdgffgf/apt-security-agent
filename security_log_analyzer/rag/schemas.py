from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RagChunk:
    chunk_id: str
    source_path: str
    framework: str
    section: str
    chunk_text: str
    tags: list[str] = field(default_factory=list)
    priority: int = 0


@dataclass(slots=True)
class RagHit:
    chunk: RagChunk
    score: float
    matched_terms: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RagCorpus:
    root: str
    chunks: list[RagChunk]
