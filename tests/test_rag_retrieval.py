import unittest

from security_log_analyzer.models import Finding
from security_log_analyzer.rag.retriever import retrieve_standards
from security_log_analyzer.standards import build_standard_query, build_standards_assessment


class RagRetrievalTests(unittest.TestCase):
    def test_sql_injection_retrieves_owasp_and_mitre_guidance(self):
        query = build_standard_query(
            [
                Finding(
                    kind="sql_injection",
                    description="请求包含 union select",
                    details={"decoded_path": "/?id=1 union select 1,2"},
                )
            ],
            log_type="web_access",
        )

        hits = retrieve_standards(query, top_k=5)
        sections = {(hit.chunk.framework, hit.chunk.section) for hit in hits}

        self.assertIn(("owasp", "A03 Injection"), sections)
        self.assertIn(("mitre", "T1190 Exploit Public-Facing Application"), sections)

    def test_bruteforce_retrieves_authentication_and_t1110_guidance(self):
        assessment = build_standards_assessment(
            [Finding(kind="bruteforce", description="同一 IP 连续失败登录", count=5)],
            log_type="ssh_login",
        )
        sections = {(hit.chunk.framework, hit.chunk.section) for hit in assessment.retrieved_context}

        self.assertIn(("owasp", "A07 Identification and Authentication Failures"), sections)
        self.assertIn(("mitre", "T1110 Brute Force"), sections)
        self.assertGreaterEqual(assessment.risk.score, 80)

    def test_off_hours_access_retrieves_nist_access_control_guidance(self):
        assessment = build_standards_assessment(
            [Finding(kind="off_hours_access", description="凌晨成功登录")],
            log_type="cloud_login",
        )
        sections = {(hit.chunk.framework, hit.chunk.section) for hit in assessment.retrieved_context}

        self.assertIn(("nist", "PR.AC-4 Access Permissions and Authorizations Managed"), sections)


if __name__ == "__main__":
    unittest.main()
