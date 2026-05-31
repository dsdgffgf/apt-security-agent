import importlib
import os
import unittest
from unittest.mock import patch

from security_log_analyzer.qwen_assistant import (
    QWEN_TOOL_NAMES,
    QwenAgentUnavailableError,
    build_qwen_function_list,
    build_qwen_llm_config,
    create_qwen_security_assistant,
)


class QwenAssistantTests(unittest.TestCase):
    def test_exposes_design3_tool_names(self):
        # QWEN_TOOL_NAMES = TOOL_NAMES, which now includes all 27+ tools
        self.assertIn("read_log_file", QWEN_TOOL_NAMES)
        self.assertIn("parse_log", QWEN_TOOL_NAMES)
        self.assertIn("summarize_log", QWEN_TOOL_NAMES)
        self.assertIn("extract_basic_patterns", QWEN_TOOL_NAMES)
        self.assertIn("risk_hint", QWEN_TOOL_NAMES)
        self.assertIn("format_evidence", QWEN_TOOL_NAMES)
        # Also includes pentest / attack / apt tools
        self.assertIn("port_scan", QWEN_TOOL_NAMES)
        self.assertIn("osint_recon", QWEN_TOOL_NAMES)

        # build_qwen_function_list filters by mode
        self.assertEqual(build_qwen_function_list(mode="defense"),
                         ["read_log_file", "parse_log", "summarize_log",
                          "extract_basic_patterns", "risk_hint", "format_evidence"])
        self.assertIn("port_scan", build_qwen_function_list(mode="pentest"))
        self.assertIn("payload_gen", build_qwen_function_list(mode="attack"))
        self.assertIn("osint_recon", build_qwen_function_list(mode="apt"))

    def test_missing_qwen_agent_dependency_has_clear_error(self):
        with patch.object(importlib, "import_module", side_effect=ImportError("missing")):
            with self.assertRaises(QwenAgentUnavailableError) as ctx:
                create_qwen_security_assistant()

        self.assertIn("pip install qwen-agent", str(ctx.exception))

    def test_qwen_config_uses_deepseek_model_by_default(self):
        with patch.dict(
            os.environ,
            {"DEEPSEEK_API_KEY": "sk-test-key"},
            clear=True,
        ):
            # defense 模式默认用 Flash
            config = build_qwen_llm_config(mode="defense")

        self.assertEqual(config["model"], "deepseek-v4-flash")
        self.assertEqual(config["model_server"], "https://api.deepseek.com/v1")
        self.assertEqual(config["api_key"], "sk-test-key")
        self.assertEqual(config.get("model_type"), "deepseek")
        self.assertGreaterEqual(config["generate_cfg"]["max_tokens"], 4096)
        self.assertEqual(config["generate_cfg"]["temperature"], 0)

    def test_qwen_config_uses_pro_for_apt_mode(self):
        with patch.dict(
            os.environ,
            {"DEEPSEEK_API_KEY": "sk-test-key"},
            clear=True,
        ):
            # apt 模式默认用 Pro
            config = build_qwen_llm_config(mode="apt")

        self.assertEqual(config["model"], "deepseek-v4-pro")
        self.assertEqual(config["model_server"], "https://api.deepseek.com/v1")
        self.assertEqual(config["api_key"], "sk-test-key")
        self.assertEqual(config.get("model_type"), "deepseek")
        self.assertGreaterEqual(config["generate_cfg"]["max_tokens"], 4096)
        self.assertEqual(config["generate_cfg"]["temperature"], 0)

    def test_qwen_config_requires_deepseek_key(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_qwen_llm_config()

        self.assertIn("DEEPSEEK_API_KEY", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
