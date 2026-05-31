import unittest

from security_log_analyzer.models import Finding
from security_log_analyzer.rag.corpus import load_standard_corpus
from security_log_analyzer.standards import build_standards_assessment


class RagExpansionTests(unittest.TestCase):
    def test_corpus_includes_cwe_family(self):
        frameworks = {chunk.framework for chunk in load_standard_corpus()}

        self.assertIn("cwe", frameworks)
        self.assertTrue({"owasp", "mitre", "nist", "cwe"}.issubset(frameworks))

    def test_injection_assessment_surfaces_cwe_references_and_hits(self):
        assessment = build_standards_assessment(
            [
                Finding(kind="sql_injection", description="SQL 注入"),
                Finding(kind="command_injection", description="命令注入"),
            ],
            log_type="web_access",
        )

        refs = {(reference.framework, reference.code) for reference in assessment.references}
        hit_frameworks = {hit.chunk.framework for hit in assessment.retrieved_context}

        self.assertIn(("CWE", "CWE-89"), refs)
        self.assertIn(("CWE", "CWE-78"), refs)
        self.assertIn("cwe", hit_frameworks)


if __name__ == "__main__":
    unittest.main()
