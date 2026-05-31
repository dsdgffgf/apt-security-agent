import tempfile
import unittest
from pathlib import Path

from scripts.build_rag_index import build_index
from scripts.validate_standards_corpus import (
    validate_standard_corpus,
    validate_standard_corpus_chunks,
)
from security_log_analyzer.rag.retriever import retrieve_standards
from security_log_analyzer.rag.schemas import RagChunk


class RagToolTests(unittest.TestCase):
    def test_validate_corpus_passes_default_standards_documents(self):
        result = validate_standard_corpus()

        self.assertTrue(result.ok, result.errors)
        self.assertGreater(result.chunk_count, 0)
        self.assertTrue({"owasp", "mitre", "nist", "cwe"}.issubset(result.frameworks))

    def test_validate_corpus_detects_malformed_chunks(self):
        result = validate_standard_corpus_chunks(
            [
                RagChunk(
                    chunk_id="",
                    source_path="",
                    framework="owasp",
                    section="",
                    chunk_text="",
                    tags=[],
                )
            ]
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("chunk_id" in error for error in result.errors))
        self.assertTrue(any("missing framework documents" in error for error in result.errors))

    def test_build_rag_index_regenerates_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            index_path = Path(tmpdir) / "rag_index.json"

            chunks, output_path = build_index(index_path=index_path)

            self.assertEqual(output_path, index_path)
            self.assertTrue(index_path.exists())
            self.assertGreater(len(chunks), 0)

    def test_lexical_fallback_retrieval_works_without_vector_backend(self):
        hits = retrieve_standards("OWASP A03 sql injection public-facing application", top_k=3)
        sections = {hit.chunk.section for hit in hits}

        self.assertIn("A03 Injection", sections)


if __name__ == "__main__":
    unittest.main()
