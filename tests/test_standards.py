import unittest

from security_log_analyzer.models import Finding
from security_log_analyzer.standards import build_standards_assessment


class StandardsLayerTests(unittest.TestCase):
    def test_build_standards_assessment_maps_findings_to_industry_frameworks(self):
        findings = [
            Finding(kind="bruteforce", description="SSH brute force"),
            Finding(kind="sql_injection", description="SQL injection"),
            Finding(kind="off_hours_access", description="Off-hours access"),
        ]

        assessment = build_standards_assessment(findings, log_type="mixed")

        frameworks = {reference.framework for reference in assessment.references}
        codes = {(reference.framework, reference.code) for reference in assessment.references}

        self.assertIn("OWASP", frameworks)
        self.assertIn("MITRE ATT&CK", frameworks)
        self.assertIn("NIST CSF", frameworks)
        self.assertIn(("OWASP", "A03"), codes)
        self.assertIn(("MITRE ATT&CK", "T1110"), codes)
        self.assertIn(("NIST CSF", "DE.CM-7"), codes)
        self.assertGreaterEqual(assessment.risk.score, 80)
        self.assertIn("OWASP", assessment.summary)
        self.assertIn("MITRE ATT&CK", assessment.summary)
        self.assertTrue(assessment.retrieval_query)
        self.assertTrue(assessment.retrieved_context)
        self.assertIn("检索到", assessment.summary)


if __name__ == "__main__":
    unittest.main()
