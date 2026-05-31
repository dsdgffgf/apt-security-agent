import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class CliTests(unittest.TestCase):
    def test_agent_flag_requests_qwen_agent_analysis(self):
        from security_log_analyzer.__main__ import main

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "login.log"
            log_path.write_text("2026-05-13 sshd: Failed password for root from 1.2.3.4", encoding="utf-8")

            fake_analysis = SimpleNamespace(
                summary=None,
                findings=[],
                tool_risk=None,
                parse_result=SimpleNamespace(log_type="ssh_login"),
                source=str(log_path),
                selected_tools=[],
                judgment=None,
                failed_login_stats=None,
                tool_findings={},
                standards=None,
                qwen_agent_used=True,
            )
            stdout = io.StringIO()
            with (
                patch("security_log_analyzer.__main__.analyze_security_logs", return_value=fake_analysis) as analyze,
                patch("security_log_analyzer.__main__.build_security_report", return_value="REPORT"),
                patch("sys.stdout", stdout),
            ):
                exit_code = main([str(log_path), "--agent"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue().strip(), "REPORT")
        self.assertTrue(analyze.call_args.kwargs["qwen_agent_used"])

    def test_directory_input_runs_every_log_file_in_single_mode(self):
        from security_log_analyzer.__main__ import main

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "one.log"
            second = root / "two.log"
            ignored = root / "note.txt"
            first.write_text("2026-05-13 sshd: Failed password for root from 1.2.3.4", encoding="utf-8")
            second.write_text("2026-05-13 web: GET /login?id=1 OR 1=1", encoding="utf-8")
            ignored.write_text("skip me", encoding="utf-8")

            def fake_analysis(log_input, *, source, qwen_agent_used=False, **_kwargs):
                return SimpleNamespace(
                    summary=SimpleNamespace(),
                    findings=[],
                    tool_risk=SimpleNamespace(),
                    parse_result=SimpleNamespace(log_type="mixed"),
                    source=source,
                    selected_tools=[],
                    judgment=SimpleNamespace(final_risk=SimpleNamespace(score=8, level="低危"), analysis_path=[]),
                    failed_login_stats=None,
                    tool_findings={},
                    standards=None,
                    qwen_agent_used=qwen_agent_used,
                )

            stdout = io.StringIO()
            with (
                patch("security_log_analyzer.__main__.analyze_security_logs", side_effect=fake_analysis) as analyze,
                patch("security_log_analyzer.__main__.build_security_report", side_effect=lambda **kwargs: f"REPORT:{kwargs['source']}"),
                patch("sys.stdout", stdout),
            ):
                exit_code = main([str(root)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(analyze.call_count, 2)
        self.assertIn("one.log", stdout.getvalue())
        self.assertIn("two.log", stdout.getvalue())
        self.assertNotIn("note.txt", stdout.getvalue())

    def test_compare_mode_runs_both_modes_for_each_log_file(self):
        from security_log_analyzer.__main__ import main

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "one.log"
            second = root / "two.log"
            first.write_text("2026-05-13 sshd: Failed password for root from 1.2.3.4", encoding="utf-8")
            second.write_text("2026-05-13 web: GET /login?id=1 OR 1=1", encoding="utf-8")

            def fake_analysis(log_input, *, source, qwen_agent_used=False, **_kwargs):
                score = 8 if not qwen_agent_used else 92
                level = "低危" if not qwen_agent_used else "严重"
                return SimpleNamespace(
                    summary=SimpleNamespace(),
                    findings=[],
                    tool_risk=SimpleNamespace(score=8, level="低危", reasons=[]),
                    parse_result=SimpleNamespace(log_type="mixed"),
                    source=source,
                    selected_tools=[],
                    judgment=SimpleNamespace(
                        final_risk=SimpleNamespace(score=score, level=level),
                        suspected_attack=qwen_agent_used,
                        attack_types=["SQL注入攻击"] if qwen_agent_used else [],
                        analysis_path=[],
                    ),
                    failed_login_stats=None,
                    tool_findings={},
                    standards=None,
                    qwen_agent_used=qwen_agent_used,
                )

            stdout = io.StringIO()
            with (
                patch("security_log_analyzer.__main__.analyze_security_logs", side_effect=fake_analysis) as analyze,
                patch("sys.stdout", stdout),
            ):
                exit_code = main([str(root), "--compare"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(analyze.call_count, 4)
        self.assertIn("one.log", stdout.getvalue())
        self.assertIn("two.log", stdout.getvalue())
        self.assertIn("本地", stdout.getvalue())
        self.assertIn("智能体", stdout.getvalue())
        self.assertIn("92", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
