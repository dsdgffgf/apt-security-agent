import unittest

from security_log_analyzer import analyze_security_logs, build_security_report
from security_log_analyzer.models import Finding, RiskResult, SummaryData


SAMPLE_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:10 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:15 sshd[123]: Accepted password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:01:00 sshd[123]: Failed password for guest from 5.6.7.8 port 22 ssh2
2026-05-13 08:01:05 sshd[123]: Failed password for test from 5.6.7.8 port 22 ssh2
2026-05-13 08:01:10 sshd[123]: Failed password for admin from 5.6.7.8 port 22 ssh2
2026-05-13 08:02:00 8.8.8.8 - - [13/May/2026:08:02:00 +0800] "GET /?id=1%20union%20select%201,2 HTTP/1.1" 200 100 "-" "curl/8.0"
2026-05-13 08:02:05 8.8.8.8 - - [13/May/2026:08:02:05 +0800] "GET /../../etc/passwd HTTP/1.1" 404 50 "-" "curl/8.0"
2026-05-13 08:02:10 8.8.8.8 - - [13/May/2026:08:02:10 +0800] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "curl/8.0"
"""


class ReportTests(unittest.TestCase):
    def test_build_security_report_is_concise(self):
        analysis = analyze_security_logs(SAMPLE_LOG, source="sample.log")

        report = build_security_report(
            analysis.summary,
            analysis.findings,
            analysis.tool_risk,
            log_type=analysis.parse_result.log_type,
            source=analysis.source,
            selected_tools=analysis.selected_tools,
            judgment=analysis.judgment,
            failed_login_stats=analysis.failed_login_stats,
            tool_findings=analysis.tool_findings,
            standards=analysis.standards,
            qwen_agent_used=True,
        )

        self.assertTrue(report.startswith("# 日志安全分析报告"))
        self.assertIn("## 1. 分析对象", report)
        self.assertIn("## 2. 结论摘要", report)
        self.assertIn("## 3. 关键证据", report)
        self.assertIn("## 4. 行业标准依据", report)
        self.assertIn("## 5. 处置建议", report)
        self.assertLessEqual(sum(1 for line in report.splitlines() if line.startswith("## ")), 5)
        self.assertIn("OWASP A03", report)
        self.assertIn("MITRE ATT&CK T1110", report)
        self.assertIn("最终风险", report)
        self.assertIn("SQL 注入", report)
        self.assertIn("目录遍历", report)
        self.assertIn("XSS", report)
        self.assertNotIn("## 7. 风险等级", report)
        self.assertNotIn("## 10. 后续加固建议", report)

    def test_report_redacts_authorization_bearer_tokens_from_evidence(self):
        report = build_security_report(
            SummaryData(
                total_events=1,
                success_events=0,
                failure_events=1,
                ip_count=1,
                account_count=0,
            ),
            [
                Finding(
                    kind="api_abnormal_call",
                    description="API 异常调用",
                    ip="9.9.9.9",
                    evidence=["2026-05-13 GET /api Authorization: Bearer secret-token-123"],
                )
            ],
            RiskResult(score=60, level="中危", reasons=["API 异常调用"]),
            log_type="api_access",
            source="api.log",
        )

        self.assertNotIn("secret-token-123", report)
        self.assertIn("Authorization: Bearer [REDACTED]", report)


if __name__ == "__main__":
    unittest.main()
