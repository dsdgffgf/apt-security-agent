from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator, List, Literal, Optional

import httpx

from .config import MIMO_DEFAULT_MODEL, resolve_mimo_base_url
from qwen_agent.llm.base import BaseChatModel, ModelServiceError, register_llm
from qwen_agent.llm.schema import ASSISTANT, FUNCTION, SYSTEM, USER, FunctionCall, Message
from qwen_agent.log import logger


DEFAULT_MIMO_MODEL = MIMO_DEFAULT_MODEL
_TEXT_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(?P<name>[A-Za-z_][A-Za-z0-9_]*)>\s*(?P<body>.*?)(?:</function>\s*</tool_call>|</function>|</tool_call>|$)",
    re.S,
)
_TEXT_TOOL_PARAMETER_RE = re.compile(
    r"<parameter=(?P<name>[^>]+)>(?P<value>.*?)(?=<parameter=|</function>|</tool_call>|$)",
    re.S,
)


@register_llm("mimo_anthropic")
class MimoAnthropicChatModel(BaseChatModel):
    def __init__(self, cfg: Optional[dict] = None):
        super().__init__(cfg)
        cfg = cfg or {}

        self.model = self.model or cfg.get("model") or DEFAULT_MIMO_MODEL
        self.api_key = _resolve_api_key(cfg)
        self.base_url = resolve_mimo_base_url(
            api_key=self.api_key,
            model_server=cfg.get("model_server") or cfg.get("base_url") or cfg.get("api_base"),
        )
        self.request_timeout = cfg.get("request_timeout") or cfg.get("timeout") or 120
        self.curl_fallback = cfg.get("curl_fallback", True)
        self.curl_path = cfg.get("curl_path") or os.getenv("MIMO_CURL_PATH") or "curl.exe"
        self._client = httpx.Client(
            timeout=self.request_timeout,
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    @property
    def support_multimodal_input(self) -> bool:
        return False

    @property
    def support_multimodal_output(self) -> bool:
        return False

    @property
    def support_audio_input(self) -> bool:
        return False

    def _chat_with_functions(
        self,
        messages: List[Message],
        functions: List[dict],
        stream: bool,
        delta_stream: bool,
        generate_cfg: dict,
        lang: Literal["en", "zh"],
    ) -> Iterator[List[Message]] | List[Message]:
        payload = self._build_payload(messages, functions, generate_cfg)
        if stream:
            return self._stream_response(payload)
        return self._request_and_parse(payload)

    def _chat_stream(
        self,
        messages: List[Message],
        delta_stream: bool,
        generate_cfg: dict,
    ) -> Iterator[List[Message]]:
        payload = self._build_payload(messages, None, generate_cfg)
        return self._stream_response(payload)

    def _chat_no_stream(
        self,
        messages: List[Message],
        generate_cfg: dict,
    ) -> List[Message]:
        payload = self._build_payload(messages, None, generate_cfg)
        return self._request_and_parse(payload)

    def _stream_response(self, payload: dict[str, Any]) -> Iterator[List[Message]]:
        yield self._request_and_parse(payload)

    def _request_and_parse(self, payload: dict[str, Any]) -> List[Message]:
        logger.debug(f"MiMo Anthropic request payload: {json.dumps(payload, ensure_ascii=False, sort_keys=True)}")
        response = self._post_json(payload)
        messages = _response_to_messages(response)
        logger.debug(f"MiMo Anthropic response messages: {messages}")
        return messages

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = self._messages_url()
        try:
            response = self._client.post(url, json=payload)
        except httpx.RequestError as exc:
            if self.curl_fallback:
                return self._post_json_with_curl(url, payload)
            raise ModelServiceError(exception=exc)

        if response.status_code >= 400:
            error = _parse_error_response(response)
            raise ModelServiceError(
                code=str(response.status_code),
                message=_format_error_message(error, response.text),
                extra=error,
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ModelServiceError(exception=exc, code=str(response.status_code), message="Invalid JSON response.")
        if not isinstance(data, dict):
            raise ModelServiceError(code=str(response.status_code), message="Unexpected response payload.")
        return data

    def _post_json_with_curl(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as body_file:
                json.dump(payload, body_file, ensure_ascii=False)
                body_path = Path(body_file.name)

            config = "\n".join(
                [
                    f'url = "{_curl_config_escape(url)}"',
                    f'header = "api-key: {_curl_config_escape(self.api_key)}"',
                    'header = "Content-Type: application/json"',
                    'header = "anthropic-version: 2023-06-01"',
                    "",
                ]
            )
            completed = subprocess.run(
                [
                    self.curl_path,
                    "--silent",
                    "--show-error",
                    "--location",
                    "--request",
                    "POST",
                    "--config",
                    "-",
                    "--data-binary",
                    f"@{body_path}",
                    "--write-out",
                    "\n%{http_code}",
                ],
                input=config,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.request_timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ModelServiceError(exception=exc)
        finally:
            if body_path:
                body_path.unlink(missing_ok=True)

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        if completed.returncode != 0:
            raise ModelServiceError(message=stderr.strip() or "curl request failed.")

        try:
            response_text, status_text = stdout.rsplit("\n", 1)
            status_code = int(status_text.strip())
        except ValueError as exc:
            raise ModelServiceError(exception=exc, message="Invalid curl response.")

        if status_code >= 400:
            error = _parse_error_text(response_text)
            raise ModelServiceError(code=str(status_code), message=_format_error_message(error, response_text), extra=error)

        try:
            data = json.loads(response_text)
        except ValueError as exc:
            raise ModelServiceError(exception=exc, code=str(status_code), message="Invalid JSON response.")
        if not isinstance(data, dict):
            raise ModelServiceError(code=str(status_code), message="Unexpected response payload.")
        return data

    def _messages_url(self) -> str:
        if self.base_url.endswith("/v1/messages"):
            return self.base_url
        if self.base_url.endswith("/anthropic"):
            return f"{self.base_url}/v1/messages"
        if self.base_url.endswith("/anthropic/"):
            return f"{self.base_url.rstrip('/')}/v1/messages"
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/messages"
        return f"{self.base_url.rstrip('/')}/v1/messages"

    def _build_payload(
        self,
        messages: List[Message],
        functions: list[dict] | None,
        generate_cfg: dict,
    ) -> dict[str, Any]:
        local_cfg = copy.deepcopy(generate_cfg)
        system_text, anthropic_messages = _convert_messages(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": int(
                local_cfg.pop(
                    "max_tokens",
                    local_cfg.pop("max_completion_tokens", self.generate_cfg.get("max_tokens", 1024)),
                )
            ),
        }

        if system_text:
            payload["system"] = system_text

        temperature = local_cfg.pop("temperature", self.generate_cfg.get("temperature"))
        if temperature is not None:
            payload["temperature"] = temperature

        top_p = local_cfg.pop("top_p", self.generate_cfg.get("top_p"))
        if top_p is not None:
            payload["top_p"] = top_p

        stop_sequences = local_cfg.pop("stop_sequences", local_cfg.pop("stop", None))
        if stop_sequences:
            if isinstance(stop_sequences, str):
                stop_sequences = [stop_sequences]
            payload["stop_sequences"] = stop_sequences

        for key in (
            "seed",
            "lang",
            "max_input_tokens",
            "incremental_output",
            "skip_stopword_postproc",
            "parallel_function_calls",
            "function_choice",
            "thought_in_content",
            "cache_dir",
        ):
            local_cfg.pop(key, None)

        if functions:
            payload["tools"] = [_convert_tool_spec(tool) for tool in functions]
            payload["tool_choice"] = {"type": "auto"}

        return payload


def _resolve_api_key(cfg: dict[str, Any]) -> str:
    key = cfg.get("api_key")
    if not key:
        key = os.getenv("MIMO_API_KEY") or os.getenv("XIAOMI_API_KEY") or os.getenv("XIAOMI_MIMO_API_KEY")
    key = (key or "").strip()
    if not key:
        raise ValueError("Xiaomi MiMo API credential is not configured in the local backend environment.")
    return key


def _convert_messages(messages: List[Message]) -> tuple[str | None, list[dict[str, Any]]]:
    system_chunks: list[str] = []
    anthropic_messages: list[dict[str, Any]] = []

    for message in messages:
        role = message.role
        if role == SYSTEM:
            text = _message_text(message.content)
            if text:
                system_chunks.append(text)
            continue

        if role == USER:
            anthropic_messages.append({"role": "user", "content": _text_blocks(_message_text(message.content))})
            continue

        if role == FUNCTION:
            tool_use_id = (message.extra or {}).get("function_id", "1")
            anthropic_messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": _message_text(message.content),
                            "is_error": False,
                        }
                    ],
                }
            )
            continue

        if role == ASSISTANT:
            content_blocks: list[dict[str, Any]] = []
            reasoning_text = _message_text(message.reasoning_content)
            if reasoning_text:
                content_blocks.append({"type": "thinking", "thinking": reasoning_text})
            content_text = _message_text(message.content)
            if content_text:
                content_blocks.append({"type": "text", "text": content_text})
            if message.function_call:
                content_blocks.append(
                    {
                        "type": "tool_use",
                        "id": (message.extra or {}).get("function_id", "1"),
                        "name": message.function_call.name,
                        "input": _safe_json_loads(message.function_call.arguments),
                    }
                )
            if content_blocks:
                anthropic_messages.append({"role": "assistant", "content": content_blocks})
            continue

        anthropic_messages.append({"role": "user", "content": _message_text(message.content)})

    system_text = "\n\n".join(chunk for chunk in system_chunks if chunk) or None
    return system_text, anthropic_messages


def _convert_tool_spec(tool: dict[str, Any]) -> dict[str, Any]:
    parameters = tool.get("parameters") or tool.get("input_schema") or {}
    input_schema = _normalize_input_schema(parameters)
    return {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "type": "custom",
        "input_schema": input_schema,
    }


def _normalize_input_schema(parameters: Any) -> dict[str, Any]:
    if isinstance(parameters, dict) and parameters.get("type") == "object":
        schema = copy.deepcopy(parameters)
        schema.setdefault("properties", {})
        schema.setdefault("required", [])
        return schema

    if isinstance(parameters, list):
        properties: dict[str, Any] = {}
        required: list[str] = []
        for item in parameters:
            name = item.get("name")
            if not name:
                continue
            entry: dict[str, Any] = {"type": _normalize_json_type(item.get("type"))}
            if item.get("description"):
                entry["description"] = item["description"]
            if item.get("enum"):
                entry["enum"] = item["enum"]
            properties[name] = entry
            if item.get("required"):
                required.append(name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    return {
        "type": "object",
        "properties": {},
        "required": [],
    }


def _normalize_json_type(value: Any) -> str:
    if value in {"integer", "number", "boolean", "array", "object"}:
        return str(value)
    return "string"


def _message_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                if "text" in item and item["text"] is not None:
                    parts.append(str(item["text"]))
                elif "thinking" in item and item["thinking"] is not None:
                    parts.append(str(item["thinking"]))
                elif "content" in item and item["content"] is not None:
                    parts.append(_message_text(item["content"]))
            else:
                parts.append(str(item))
        return "".join(parts)
    if isinstance(value, dict):
        if "text" in value and value["text"] is not None:
            return str(value["text"])
        if "thinking" in value and value["thinking"] is not None:
            return str(value["thinking"])
        if "content" in value and value["content"] is not None:
            return _message_text(value["content"])
    return str(value)


def _text_blocks(text: str) -> list[dict[str, str]]:
    return [{"type": "text", "text": text}]


def _safe_json_loads(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _response_to_messages(response: dict[str, Any]) -> list[Message]:
    content = response.get("content") or []
    if not isinstance(content, list):
        content = [content]

    reasoning_texts: list[str] = []
    text_blocks: list[str] = []
    tool_calls: list[Message] = []

    for block in content:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "thinking" and block.get("thinking"):
            reasoning_texts.append(str(block["thinking"]))
            continue
        if block_type == "text" and block.get("text"):
            text = str(block["text"])
            text_tool_calls = _parse_text_tool_calls(text)
            if text_tool_calls:
                tool_calls.extend(text_tool_calls)
            else:
                text_blocks.append(text)
            continue
        if block_type == "tool_use":
            tool_calls.append(
                Message(
                    role=ASSISTANT,
                    content="",
                    function_call=FunctionCall(
                        name=str(block.get("name", "")),
                        arguments=json.dumps(block.get("input", {}), ensure_ascii=False),
                    ),
                    extra={"function_id": str(block.get("id", "1"))},
                )
            )

    output: list[Message] = []
    reasoning_text = "".join(reasoning_texts)
    text_content = "".join(text_blocks)

    if tool_calls:
        first_tool_call = tool_calls[0]
        first_tool_call.content = text_content
        if reasoning_text:
            first_tool_call.reasoning_content = reasoning_text
        output.append(first_tool_call)
        output.extend(tool_calls[1:])
    elif reasoning_text:
        output.append(Message(role=ASSISTANT, content=text_content, reasoning_content=reasoning_text))
    elif text_content:
        output.append(Message(role=ASSISTANT, content=text_content))
    if not output:
        output.append(Message(role=ASSISTANT, content=""))
    return output


def _parse_text_tool_calls(text: str) -> list[Message]:
    matches = list(_TEXT_TOOL_CALL_RE.finditer(text))
    if not matches:
        return []

    messages: list[Message] = []
    prefix = text[: matches[0].start()].strip()
    for index, match in enumerate(matches):
        tool_name = match.group("name").strip()
        params: dict[str, Any] = {}
        for parameter in _TEXT_TOOL_PARAMETER_RE.finditer(match.group("body") or ""):
            param_name = parameter.group("name").strip()
            raw_value = parameter.group("value").strip()
            params[param_name] = _safe_json_loads(raw_value)
        tool_call_id = _text_tool_call_id(text, index)
        messages.append(
            Message(
                role=ASSISTANT,
                content=prefix if index == 0 else "",
                function_call=FunctionCall(
                    name=tool_name,
                    arguments=json.dumps(params, ensure_ascii=False),
                ),
                extra={"function_id": tool_call_id},
            )
        )
    return messages


def _text_tool_call_id(text: str, index: int) -> str:
    digest = hashlib.sha1(f"{index}:{text}".encode("utf-8")).hexdigest()[:12]
    return f"text_tool_call_{digest}"


def _parse_error_response(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {"message": response.text}

    return _parse_error_data(data, response.text)


def _parse_error_text(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except ValueError:
        return {"message": text}
    return _parse_error_data(data, text)


def _parse_error_data(data: Any, fallback: str) -> dict[str, Any]:
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            return error
        if "message" in data:
            return data
    return {"message": fallback}


def _format_error_message(error: dict[str, Any], fallback: str) -> str:
    message = str(error.get("message") or fallback).strip()
    param = str(error.get("param") or "").strip()
    if param and param not in message:
        return f"{message}: {param}"
    return message


def _curl_config_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
