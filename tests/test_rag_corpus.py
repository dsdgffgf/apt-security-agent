import tempfile
import unittest
from pathlib import Path

from security_log_analyzer.rag.corpus import default_standards_corpus_root, load_standard_corpus
from security_log_analyzer.rag.index import build_rag_index, load_rag_index


class RagCorpusTests(unittest.TestCase):
    def test_load_standard_corpus_discovers_framework_families(self):
        corpus_root = default_standards_corpus_root()
        self.assertTrue(corpus_root.exists())

        chunks = load_standard_corpus(corpus_root)

        self.assertTrue(chunks)
        frameworks = {chunk.framework for chunk in chunks}
        self.assertTrue({"owasp", "mitre", "nist"}.issubset(frameworks))
        self.assertTrue(any(chunk.section for chunk in chunks))
        self.assertTrue(any("Injection" in chunk.chunk_text or "A07" in chunk.chunk_text for chunk in chunks))

    def test_build_and_load_rag_index_round_trips(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            index_path = Path(tmpdir) / "rag_index.json"

            chunks = build_rag_index(index_path=index_path)
            loaded = load_rag_index(index_path=index_path)
            self.assertTrue(index_path.exists())

        self.assertEqual(len(chunks), len(loaded))
        self.assertEqual({chunk.chunk_id for chunk in chunks}, {chunk.chunk_id for chunk in loaded})


if __name__ == "__main__":
    unittest.main()
