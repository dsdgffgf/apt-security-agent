from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_log_analyzer.rag.corpus import load_standard_corpus
from security_log_analyzer.rag.schemas import RagChunk


REQUIRED_FRAMEWORKS = {"owasp", "mitre", "nist", "cwe"}


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    errors: list[str]
    chunk_count: int
    frameworks: tuple[str, ...]


def validate_standard_corpus(root: str | Path | None = None) -> ValidationResult:
    return validate_standard_corpus_chunks(load_standard_corpus(root))


def validate_standard_corpus_chunks(chunks: list[RagChunk]) -> ValidationResult:
    errors: list[str] = []
    frameworks = tuple(sorted({chunk.framework for chunk in chunks if chunk.framework}))

    if not chunks:
        errors.append("standards corpus is empty")

    missing = REQUIRED_FRAMEWORKS - set(frameworks)
    if missing:
        errors.append(f"missing framework documents: {', '.join(sorted(missing))}")

    for chunk in chunks:
        prefix = chunk.chunk_id or "<missing chunk_id>"
        if not chunk.chunk_id:
            errors.append("chunk is missing chunk_id")
        if not chunk.source_path:
            errors.append(f"{prefix}: missing source_path")
        if not chunk.framework:
            errors.append(f"{prefix}: missing framework")
        if not chunk.section:
            errors.append(f"{prefix}: missing section")
        if not chunk.chunk_text.strip():
            errors.append(f"{prefix}: missing chunk_text")
        if not chunk.tags:
            errors.append(f"{prefix}: missing tags")

    return ValidationResult(
        ok=not errors,
        errors=errors,
        chunk_count=len(chunks),
        frameworks=frameworks,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the local standards RAG corpus.")
    parser.add_argument("--corpus-root", help="Optional standards corpus root.")
    args = parser.parse_args(argv)

    result = validate_standard_corpus(args.corpus_root)
    if result.ok:
        print(
            f"Standards corpus OK: {result.chunk_count} chunks; "
            f"frameworks={', '.join(result.frameworks)}"
        )
        return 0

    print("Standards corpus validation failed:")
    for error in result.errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
