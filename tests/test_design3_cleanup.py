import unittest

import security_log_analyzer
from security_log_analyzer import analyze_security_logs
from security_log_analyzer.tools import TOOL_NAMES, run_local_tool


LOGIN_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
"""


class Design3CleanupTests(unittest.TestCase):
    def test_only_design3_tool_names_are_available(self):
        expected_tools = [
            "read_log_file",
            "parse_log",
            "summarize_log",
            "extract_basic_patterns",
            "risk_hint",
            "format_evidence",
        ]
        for tool in expected_tools:
            self.assertIn(tool, TOOL_NAMES, f"Expected tool '{tool}' to be in TOOL_NAMES")

        for removed_tool in [
            "get_xiaomi_logs",
            "generate_summary_data",
            "detect_security_anomaly",
            "risk_score",
            "build_security_report",
        ]:
            with self.subTest(removed_tool=removed_tool):
                with self.assertRaises(ValueError):
                    run_local_tool(removed_tool, {"log_input": LOGIN_LOG})

    def test_analyze_security_logs_no_longer_accepts_design2_xiaomi_log_source(self):
        with self.assertRaises(TypeError):
            analyze_security_logs(None, use_xiaomi_api=True)

    def test_public_api_does_not_export_removed_xiaomi_log_fetcher(self):
        self.assertFalse(hasattr(security_log_analyzer, "get_xiaomi_logs"))


if __name__ == "__main__":
    unittest.main()
