import json
import tempfile
import unittest
from pathlib import Path

from security_log_analyzer import analyze_security_logs
from security_log_analyzer.agentic import SecurityAgentError


LOGIN_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:10 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:15 sshd[123]: Accepted password for root from 1.2.3.4 port 22 ssh2
"""


WEB_404_LOG = """\
2026-05-13 09:00:00 8.8.8.8 - - [13/May/2026:09:00:00 +0800] "GET /?id=1%20union%20select%201,2 HTTP/1.1" 404 100 "-" "curl/8.0"
2026-05-13 09:00:05 8.8.8.8 - - [13/May/2026:09:00:05 +0800] "GET /../../etc/passwd HTTP/1.1" 404 100 "-" "curl/8.0"
2026-05-13 09:00:10 8.8.8.8 - - [13/May/2026:09:00:10 +0800] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 404 100 "-" "curl/8.0"
"""


class AgentAnalysisTests(unittest.TestCase):
    def test_login_analysis_selects_login_tools_and_marks_possible_success(self):
        analysis = analyze_security_logs(LOGIN_LOG, source="login.log")

        self.assertEqual(analysis.parse_result.log_type, "ssh_login")
        self.assertIn("parse_log", analysis.selected_tools)
        self.assertIn("summarize_log", analysis.selected_tools)
        self.assertIn("extract_basic_patterns", analysis.selected_tools)
        self.assertIn("risk_hint", analysis.selected_tools)
        self.assertNotIn("read_log_file", analysis.selected_tools)
        self.assertIsNotNone(analysis.standards)
        self.assertGreaterEqual(analysis.standards.risk.score, 80)
        self.assertTrue(analysis.standards.retrieved_context)
        self.assertIn("OWASP", {reference.framework for reference in analysis.standards.references})
        self.assertIn("MITRE ATT&CK", {reference.framework for reference in analysis.standards.references})
        self.assertTrue(any("标准" in step for step in analysis.judgment.analysis_path))
        self.assertTrue(analysis.judgment.attack_success_assessment)
        self.assertTrue(analysis.judgment.confidence)
        self.assertGreaterEqual(analysis.judgment.final_risk.score, 80)
        self.assertTrue(analysis.judgment.has_anomaly)
        self.assertTrue(analysis.judgment.suspected_attack)

    def test_web_404_attack_features_are_attempts_with_adjusted_risk(self):
        analysis = analyze_security_logs(WEB_404_LOG, source="web.log")

        self.assertEqual(analysis.parse_result.log_type, "web_access")
        self.assertIn("extract_basic_patterns", analysis.selected_tools)
        self.assertNotIn("read_log_file", analysis.selected_tools)
        self.assertIsNotNone(analysis.standards)
        self.assertGreaterEqual(analysis.judgment.final_risk.score, analysis.standards.risk.score)
        self.assertTrue(analysis.judgment.attack_success_assessment)
        self.assertTrue(analysis.judgment.confidence)
        self.assertTrue(analysis.judgment.score_adjusted)
        self.assertLess(analysis.judgment.final_risk.score, analysis.tool_risk.score)
        self.assertIn("404", analysis.judgment.adjustment_reason)
        self.assertIn("误报", analysis.judgment.false_positive_assessment)

    def test_qwen_agent_analysis_uses_agent_output(self):
        class FakeAssistant:
            def __init__(self):
                self.calls = []

            def run_nonstream(self, messages, **kwargs):
                self.calls.append((messages, kwargs))
                return [
                    {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "selected_tools": [
                                    "parse_log",
                                    "summarize_log",
                                    "extract_basic_patterns",
                                    "risk_hint",
                                ],
                                "analysis_path": [
                                    "先检查日志",
                                    "调用 parse_log",
                                    "对照行业标准",
                                ],
                                "has_anomaly": True,
                                "suspected_attack": True,
                                "attack_types": ["暴力破解尝试"],
                                "attack_success_assessment": "智能体判定为攻击成功",
                                "false_positive_assessment": "误报可能较低",
                                "evidence_sufficiency": "证据充足",
                                "confidence": "高置信度",
                                "standards_summary": "OWASP A07 / MITRE ATT&CK T1110",
                                "standards_references": ["OWASP A07", "MITRE ATT&CK T1110"],
                                "standards_consistency": "一致",
                                "final_risk": {
                                    "score": 42,
                                    "level": "中危",
                                    "reasons": ["智能体发现异常登录"],
                                },
                                "score_adjusted": True,
                                "adjustment_reason": "智能体认为风险应上调",
                                "summary": "智能体完成了安全分析",
                            },
                            ensure_ascii=False,
                        ),
                    }
                ]

        fake_assistant = FakeAssistant()

        analysis = analyze_security_logs(
            LOGIN_LOG,
            source="login.log",
            qwen_agent_used=True,
            qwen_agent_factory=lambda: fake_assistant,
        )

        self.assertTrue(analysis.qwen_agent_used)
        self.assertEqual(analysis.judgment.attack_success_assessment, "智能体判定为攻击成功")
        self.assertEqual(analysis.judgment.analysis_path[0], "先检查日志")
        self.assertEqual(analysis.judgment.standards_consistency, "一致")
        self.assertIn("OWASP A07", analysis.judgment.standards_references)
        self.assertIn("智能体发现异常登录", analysis.agent_response)
        self.assertGreaterEqual(analysis.judgment.final_risk.score, 42)
        self.assertGreaterEqual(analysis.judgment.final_risk.score, analysis.standards.risk.score)
        self.assertTrue(analysis.judgment.score_adjusted)

        prompt = fake_assistant.calls[0][0][0]["content"]
        self.assertIn("行业标准", prompt)
        self.assertIn("OWASP A07", prompt)
        self.assertIn("MITRE ATT&CK T1110", prompt)
        self.assertIn("检索结果", prompt)
        self.assertIn("A07 Identification and Authentication Failures", prompt)

    def test_qwen_agent_failure_is_not_silently_downgraded(self):
        class BrokenAssistant:
            def run_nonstream(self, messages, **kwargs):
                raise RuntimeError("MiMo call failed")

        with self.assertRaises(SecurityAgentError) as ctx:
            analyze_security_logs(
                LOGIN_LOG,
                source="login.log",
                qwen_agent_used=True,
                qwen_agent_factory=lambda: BrokenAssistant(),
            )

        self.assertIn("Qwen agent analysis failed", str(ctx.exception))

    def test_file_path_analysis_uses_read_log_file_tool(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "login.log"
            log_path.write_text(LOGIN_LOG, encoding="utf-8")

            analysis = analyze_security_logs(log_path)

        self.assertEqual(analysis.parse_result.log_type, "ssh_login")
        self.assertIn("read_log_file", analysis.selected_tools)
        self.assertIn("parse_log", analysis.selected_tools)
        self.assertIn("summarize_log", analysis.selected_tools)
        self.assertIn("extract_basic_patterns", analysis.selected_tools)
        self.assertIn("risk_hint", analysis.selected_tools)


if __name__ == "__main__":
    unittest.main()
