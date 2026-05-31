import tempfile
import unittest
from pathlib import Path

from security_log_analyzer.tools import (
    TOOL_NAMES,
    extract_basic_patterns,
    format_evidence,
    read_log_file,
    risk_hint,
    run_local_tool,
    summarize_log,
)
from security_log_analyzer.parser import parse_log


LOGIN_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:10 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:15 sshd[123]: Accepted password for root from 1.2.3.4 port 22 ssh2
"""


class Design3ToolTests(unittest.TestCase):
    def test_design3_tool_names_are_primary(self):
        expected_prefix = [
            "read_log_file",
            "parse_log",
            "summarize_log",
            "extract_basic_patterns",
            "risk_hint",
            "format_evidence",
        ]
        for tool in expected_prefix:
            self.assertIn(tool, TOOL_NAMES, f"Expected tool '{tool}' to be in TOOL_NAMES")
        self.assertGreaterEqual(len(TOOL_NAMES), len(expected_prefix))

    def test_read_log_file_tool_reads_uploaded_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "sample.log"
            log_path.write_text(LOGIN_LOG, encoding="utf-8")

            self.assertEqual(read_log_file(log_path), LOGIN_LOG)
            result = run_local_tool("read_log_file", {"path": str(log_path)})

        self.assertEqual(result["log_text"], LOGIN_LOG)

    def test_summary_patterns_and_risk_hint_use_existing_log_analysis(self):
        records = parse_log(LOGIN_LOG).records

        summary = summarize_log(records)
        findings = extract_basic_patterns(records)
        risk = risk_hint(findings, summary)

        self.assertEqual(summary.total_events, 4)
        self.assertEqual(summary.failure_events, 3)
        self.assertTrue(any(finding.kind == "success_after_failures" for finding in findings))
        self.assertGreaterEqual(risk.score, 80)

        tool_result = run_local_tool("risk_hint", {"log_input": LOGIN_LOG})
        self.assertEqual(tool_result["level"], "严重")

    def test_format_evidence_redacts_sensitive_values(self):
        result = format_evidence(
            [
                "2026-05-13 GET /api Authorization: Bearer secret-token",
                "2026-05-13 POST /login password=plain-text",
            ]
        )

        text = result["text"]
        self.assertNotIn("secret-token", text)
        self.assertNotIn("plain-text", text)
        self.assertIn("Authorization: Bearer [REDACTED]", text)
        self.assertIn("password=[REDACTED]", text)


if __name__ == "__main__":
    unittest.main()
