from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security_log_analyzer.rag.index import DEFAULT_INDEX_PATH, build_rag_index


def build_index(
    *,
    corpus_root: str | Path | None = None,
    index_path: str | Path | None = None,
):
    output_path = Path(index_path) if index_path is not None else DEFAULT_INDEX_PATH
    chunks = build_rag_index(corpus_root=corpus_root, index_path=output_path)
    return chunks, output_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the local standards RAG index.")
    parser.add_argument("--corpus-root", help="Optional standards corpus root.")
    parser.add_argument("--index-path", help="Output JSON index path.")
    args = parser.parse_args(argv)

    chunks, output_path = build_index(corpus_root=args.corpus_root, index_path=args.index_path)
    print(f"Built {len(chunks)} RAG chunks -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
