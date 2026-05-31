from __future__ import annotations

import re
from pathlib import Path

from .schemas import RagChunk


def default_standards_corpus_root() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "standards"


def load_standard_corpus(root: str | Path | None = None) -> list[RagChunk]:
    corpus_root = Path(root) if root is not None else default_standards_corpus_root()
    if not corpus_root.exists():
        return []

    chunks: list[RagChunk] = []
    for path in sorted(corpus_root.rglob("*.md"), key=lambda value: value.as_posix().lower()):
        if not path.is_file():
            continue
        chunks.extend(_chunk_markdown_document(path, corpus_root))
    return chunks


def _chunk_markdown_document(path: Path, corpus_root: Path) -> list[RagChunk]:
    text = path.read_text(encoding="utf-8", errors="replace")
    framework = path.parent.name.lower()
    relative = path.relative_to(corpus_root).as_posix()

    sections = _split_markdown_sections(text)
    if not sections:
        sections = [(path.stem.replace("-", " ").title(), text.strip())]

    chunks: list[RagChunk] = []
    for index, (section, content) in enumerate(sections):
        content = content.strip()
        if not content:
            continue
        chunk_text = f"{section}\n\n{content}".strip()
        tags = _build_tags(framework, path.stem, section, content)
        chunks.append(
            RagChunk(
                chunk_id=f"{relative}::{index}",
                source_path=relative,
                framework=framework,
                section=section,
                chunk_text=chunk_text,
                tags=tags,
                priority=_section_priority(section),
            )
        )
    return chunks


def _split_markdown_sections(text: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    current_title: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_title, current_lines
        if current_title is None and not current_lines:
            return
        title = current_title or "Overview"
        content = "\n".join(current_lines).strip()
        if content:
            sections.append((title, content))
        current_lines = []

    for line in text.splitlines():
        heading = _extract_heading(line)
        if heading is not None:
            flush()
            current_title = heading
            continue
        current_lines.append(line)

    flush()
    return sections


def _extract_heading(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith("## "):
        return stripped[3:].strip()
    if stripped.startswith("# "):
        return stripped[2:].strip()
    return None


def _build_tags(framework: str, stem: str, section: str, content: str) -> list[str]:
    tokens = {
        framework,
        stem.lower(),
        *(_tokenize(section)),
        *(_tokenize(content)),
    }
    tags = [token for token in sorted(tokens) if token]
    return tags[:12]


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", text) if len(token) > 1}


def _section_priority(section: str) -> int:
    lowered = section.lower()
    if any(token in lowered for token in ("injection", "brute force", "authentication", "authorization", "access control")):
        return 20
    if any(token in lowered for token in ("active scanning", "monitor", "monitoring", "exploit")):
        return 10
    return 0
