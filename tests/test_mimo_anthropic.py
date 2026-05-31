import json
import subprocess
import unittest
from unittest.mock import patch

import httpx
from qwen_agent.llm.base import ModelServiceError
from qwen_agent.llm.schema import ASSISTANT, FunctionCall, Message, USER

from security_log_analyzer.mimo_anthropic import MimoAnthropicChatModel


class MimoAnthropicAdapterTests(unittest.TestCase):
    def test_token_plan_api_key_defaults_to_token_plan_base_url(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "tp-local-test-key",
                "model": "mimo-v2.5-pro",
            }
        )

        self.assertEqual(model.base_url, "https://token-plan-cn.xiaomimimo.com/anthropic")

    def test_user_text_messages_convert_to_anthropic_text_blocks(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
            }
        )

        payload = model._build_payload([Message(role=USER, content="analyze")], None, {})

        self.assertEqual(
            payload["messages"],
            [{"role": "user", "content": [{"type": "text", "text": "analyze"}]}],
        )

    def test_assistant_tool_use_content_is_always_a_block_list(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
            }
        )

        payload = model._build_payload(
            [
                Message(
                    role=ASSISTANT,
                    content="",
                    function_call=FunctionCall(name="parse_log", arguments='{"log_input":"abc"}'),
                    extra={"function_id": "toolu_123"},
                )
            ],
            None,
            {},
        )

        self.assertIsInstance(payload["messages"][0]["content"], list)
        self.assertEqual(payload["messages"][0]["content"][0]["type"], "tool_use")

    def test_request_uses_curl_fallback_when_httpx_ssl_fails(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
            }
        )

        fake_response = {
            "content": [{"type": "text", "text": "agent ok"}],
            "model": "mimo-v2.5-pro",
        }
        completed = subprocess.CompletedProcess(
            args=["curl.exe"],
            returncode=0,
            stdout=f"{json.dumps(fake_response)}\n200",
            stderr="",
        )

        with (
            patch.object(model._client, "post", side_effect=httpx.ConnectError("ssl eof")),
            patch("security_log_analyzer.mimo_anthropic.subprocess.run", return_value=completed) as run,
        ):
            output = model.chat(messages=[Message(role=USER, content="analyze")], stream=False)

        self.assertEqual(output[0].content, "agent ok")
        command_args = run.call_args.args[0]
        self.assertNotIn("secret-mimo-key", command_args)
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_curl_error_message_includes_mimo_param_detail(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
            }
        )

        error_response = {
            "error": {
                "code": "400",
                "message": "Param Incorrect",
                "param": "Not supported model unknown-model",
            }
        }
        completed = subprocess.CompletedProcess(
            args=["curl.exe"],
            returncode=0,
            stdout=f"{json.dumps(error_response)}\n400",
            stderr="",
        )

        with (
            patch.object(model._client, "post", side_effect=httpx.ConnectError("ssl eof")),
            patch("security_log_analyzer.mimo_anthropic.subprocess.run", return_value=completed),
        ):
            with self.assertRaises(ModelServiceError) as ctx:
                model.chat(messages=[Message(role=USER, content="analyze")], stream=False)

        self.assertIn("Param Incorrect", str(ctx.exception))
        self.assertIn("Not supported model unknown-model", str(ctx.exception))

    def test_tool_use_response_translates_to_qwen_messages(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
                "model_server": "https://api.xiaomimimo.com/anthropic",
            }
        )

        fake_response = {
            "content": [
                {"type": "thinking", "thinking": "need tool"},
                {"type": "text", "text": "checking logs"},
                {
                    "type": "tool_use",
                    "id": "toolu_123",
                    "name": "parse_log",
                    "input": {"log_input": "abc"},
                },
            ],
            "stop_reason": "tool_use",
            "model": "mimo-v2.5-pro",
        }

        with patch.object(model, "_post_json", return_value=fake_response) as patched:
            output = model.chat(
                messages=[Message(role=USER, content="analyze")],
                functions=[
                    {
                        "name": "parse_log",
                        "description": "Parse logs",
                        "parameters": {
                            "type": "object",
                            "properties": {"log_input": {"type": "string"}},
                            "required": ["log_input"],
                        },
                    }
                ],
                stream=False,
            )

        self.assertEqual(patched.call_count, 1)
        self.assertEqual(len(output), 1)
        self.assertEqual(output[0].content, "checking logs")
        self.assertEqual(output[0].reasoning_content, "need tool")
        self.assertEqual(output[0].function_call.name, "parse_log")
        self.assertEqual(output[0].extra["function_id"], "toolu_123")

    def test_text_tool_call_response_translates_to_qwen_function_call(self):
        model = MimoAnthropicChatModel(
            {
                "api_key": "secret-mimo-key",
                "model": "mimo-v2.5-pro",
                "model_server": "https://api.xiaomimimo.com/anthropic",
            }
        )

        fake_response = {
            "content": [
                {
                    "type": "text",
                    "text": (
                        "<tool_call>\n"
                        "<function=format_evidence>\n"
                        '<parameter=evidence>["line1", "line2"]\n'
                        "<parameter=limit>2\n"
                        "</function>\n"
                        "</tool_call>"
                    ),
                }
            ],
            "stop_reason": "end_turn",
            "model": "mimo-v2.5-pro",
        }

        with patch.object(model, "_post_json", return_value=fake_response):
            output = model.chat(
                messages=[Message(role=USER, content="analyze")],
                functions=[
                    {
                        "name": "format_evidence",
                        "description": "Format evidence",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "evidence": {"type": "array"},
                                "limit": {"type": "integer"},
                            },
                            "required": ["evidence"],
                        },
                    }
                ],
                stream=False,
            )

        self.assertEqual(len(output), 1)
        self.assertEqual(output[0].function_call.name, "format_evidence")
        self.assertEqual(json.loads(output[0].function_call.arguments), {"evidence": ["line1", "line2"], "limit": 2})


if __name__ == "__main__":
    unittest.main()
