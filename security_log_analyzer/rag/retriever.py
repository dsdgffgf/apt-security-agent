from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import re

from .corpus import load_standard_corpus
from .schemas import RagChunk, RagHit


def retrieve_standards(
    query: str | Iterable[str],
    *,
    corpus: list[RagChunk] | None = None,
    corpus_root: str | Path | None = None,
    top_k: int = 5,
) -> list[RagHit]:
    corpus_chunks = corpus if corpus is not None else load_standard_corpus(corpus_root)
    if not corpus_chunks:
        return []

    query_terms = _normalize_query(query)
    scored: list[RagHit] = []
    for chunk in corpus_chunks:
        score, matched_terms = _score_chunk(query_terms, chunk)
        if score <= 0:
            continue
        scored.append(RagHit(chunk=chunk, score=score, matched_terms=matched_terms))

    scored.sort(
        key=lambda hit: (
            -hit.score,
            _framework_priority(hit.chunk.framework),
            hit.chunk.section.lower(),
            hit.chunk.source_path.lower(),
        )
    )
    return scored[:top_k]


def _normalize_query(query: str | Iterable[str]) -> list[str]:
    if isinstance(query, str):
        raw_terms = [line.strip() for line in query.splitlines() if line.strip()]
    else:
        raw_terms = [str(item).strip() for item in query if str(item).strip()]

    terms: list[str] = []
    seen: set[str] = set()
    for term in raw_terms:
        for candidate in _split_term(term):
            candidate = candidate.strip()
            if not candidate:
                continue
            lowered = candidate.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            terms.append(candidate)
    return terms


def _split_term(term: str) -> list[str]:
    pieces = [term]
    if " / " in term:
        pieces.extend(part.strip() for part in term.split(" / ") if part.strip())
    if " - " in term:
        pieces.extend(part.strip() for part in term.split(" - ") if part.strip())
    return pieces


def _score_chunk(query_terms: list[str], chunk: RagChunk) -> tuple[float, list[str]]:
    haystack = " ".join(
        [
            chunk.framework,
            chunk.section,
            chunk.chunk_text,
            " ".join(chunk.tags),
        ]
    ).lower()

    score = 0.0
    matched_terms: list[str] = []
    for term in query_terms:
        normalized_term = term.lower()
        if not normalized_term:
            continue
        if normalized_term in haystack:
            matched_terms.append(term)
            score += _term_weight(term)
            continue
        if _token_overlap(normalized_term, haystack):
            matched_terms.append(term)
            score += 1.0

    if not matched_terms:
        return 0.0, []

    score += chunk.priority * 0.1

    if "owasp" in haystack and any(term.lower().startswith("owasp") for term in query_terms):
        score += 2.0
    if "mitre" in haystack and any("mitre" in term.lower() for term in query_terms):
        score += 2.0
    if "nist" in haystack and any("nist" in term.lower() for term in query_terms):
        score += 2.0

    return score, _dedupe(matched_terms)


def _term_weight(term: str) -> float:
    lowered = term.lower()
    if any(token in lowered for token in ("t1110", "t1190", "t1059", "t1005", "t1595", "a03", "a07", "de.cm-7", "pr.ac-4")):
        return 4.0
    if len(lowered.split()) >= 3:
        return 3.0
    if len(lowered.split()) == 2:
        return 2.0
    return 1.0


def _token_overlap(term: str, haystack: str) -> bool:
    stopwords = {
        "a",
        "an",
        "and",
        "api",
        "for",
        "in",
        "ip",
        "log",
        "of",
        "or",
        "the",
        "to",
        "with",
        "access",
        "security",
    }
    tokens = [
        token
        for token in re.findall(r"[a-z0-9]+", term.lower())
        if token and token not in stopwords
    ]
    if not tokens:
        return False
    matches = sum(1 for token in tokens if token in haystack)
    if len(tokens) <= 2:
        return matches == len(tokens)
    return matches >= max(2, len(tokens) - 1)


def _framework_priority(framework: str) -> int:
    framework = framework.lower()
    if framework == "owasp":
        return 0
    if framework == "mitre":
        return 1
    if framework == "nist":
        return 2
    return 3


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
