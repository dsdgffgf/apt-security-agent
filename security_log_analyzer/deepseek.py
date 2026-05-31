from __future__ import annotations

import copy
import os
from typing import Any, Dict, Iterator, List, Optional

import openai

from .config import DEEPSEEK_DEFAULT_MODEL, DEEPSEEK_DEFAULT_BASE_URL

if openai.__version__.startswith("0."):
    from openai.error import OpenAIError
else:
    from openai import OpenAIError

from qwen_agent.llm.base import BaseChatModel, ModelServiceError, register_llm
from qwen_agent.llm.schema import ASSISTANT, FUNCTION, FunctionCall, Message
from qwen_agent.log import logger
from qwen_agent.utils.utils import format_as_text_message


@register_llm("deepseek")
class DeepSeekChatModel(BaseChatModel):
    def __init__(self, cfg: Optional[Dict] = None):
        super().__init__(cfg)
        cfg = cfg or {}

        self.model = self.model or cfg.get("model") or DEEPSEEK_DEFAULT_MODEL
        self.api_key = _resolve_api_key(cfg)
        self.base_url = _resolve_base_url(cfg)
        self.request_timeout = cfg.get("request_timeout") or cfg.get("timeout") or 120

        api_kwargs: Dict[str, Any] = {}
        if self.base_url:
            api_kwargs["base_url"] = self.base_url
        if self.api_key:
            api_kwargs["api_key"] = self.api_key

        self._api_kwargs = api_kwargs

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
        lang: str,
    ) -> Iterator[List[Message]] | List[Message]:
        oai_messages = _convert_messages_to_oai(messages)
        tools = _convert_functions_to_oai_tools(functions)
        gen_cfg = _clean_generate_cfg(generate_cfg)
        if tools:
            gen_cfg["tools"] = tools
        if stream:
            return self._stream_oai_chat(oai_messages, gen_cfg, delta_stream)
        return self._no_stream_oai_chat(oai_messages, gen_cfg)

    def _chat_stream(
        self,
        messages: List[Message],
        delta_stream: bool,
        generate_cfg: dict,
    ) -> Iterator[List[Message]]:
        oai_messages = _convert_messages_to_oai(messages)
        gen_cfg = _clean_generate_cfg(generate_cfg)
        return self._stream_oai_chat(oai_messages, gen_cfg, delta_stream)

    def _chat_no_stream(
        self,
        messages: List[Message],
        generate_cfg: dict,
    ) -> List[Message]:
        oai_messages = _convert_messages_to_oai(messages)
        gen_cfg = _clean_generate_cfg(generate_cfg)
        return self._no_stream_oai_chat(oai_messages, gen_cfg)

    def _chat_complete_create(self, messages: List[dict], **kwargs):
        for msg in messages:
            if "content" not in msg or msg["content"] is None:
                msg["content"] = ""
        client_kwargs = copy.deepcopy(self._api_kwargs)
        timeout = kwargs.pop("timeout", None) or kwargs.pop("request_timeout", None)
        if timeout:
            client_kwargs["timeout"] = float(timeout)
        extra_body = kwargs.pop("extra_body", {})
        client = openai.OpenAI(**client_kwargs)
        return client.chat.completions.create(
            model=self.model, messages=messages, **kwargs, extra_body=extra_body or None
        )

    def _stream_oai_chat(
        self,
        oai_messages: List[dict],
        generate_cfg: dict,
        delta_stream: bool,
    ) -> Iterator[List[Message]]:
        logger.debug(f"DeepSeek stream request cfg: {generate_cfg}")
        try:
            response = self._chat_complete_create(
                messages=oai_messages, stream=True, **generate_cfg
            )
        except OpenAIError as exc:
            raise ModelServiceError(exception=exc)

        if delta_stream:
            for chunk in response:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                        yield [Message(role=ASSISTANT, content="", reasoning_content=delta.reasoning_content)]
                    if hasattr(delta, "content") and delta.content:
                        yield [Message(role=ASSISTANT, content=delta.content)]
        else:
            full = ""
            full_reasoning = ""
            full_tool_calls: List[dict] = []
            for chunk in response:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                    full_reasoning += delta.reasoning_content
                if hasattr(delta, "content") and delta.content:
                    full += delta.content
                if hasattr(delta, "tool_calls") and delta.tool_calls:
                    for tc in delta.tool_calls:
                        existing = None
                        if tc.id:
                            existing = next((t for t in full_tool_calls if t.get("id") == tc.id), None)
                        elif full_tool_calls:
                            existing = full_tool_calls[-1]
                        if existing:
                            if tc.function and tc.function.name:
                                existing["function"]["name"] += tc.function.name
                            if tc.function and tc.function.arguments:
                                existing["function"]["arguments"] += tc.function.arguments
                        else:
                            full_tool_calls.append({
                                "id": tc.id,
                                "type": "function",
                                "function": {"name": tc.function.name or "", "arguments": tc.function.arguments or ""},
                            })
                res: List[Message] = []
                if full_reasoning:
                    res.append(Message(role=ASSISTANT, content="", reasoning_content=full_reasoning))
                if full:
                    res.append(Message(role=ASSISTANT, content=full))
                if full_tool_calls:
                    for tc in full_tool_calls:
                        res.append(Message(
                            role=ASSISTANT,
                            content="",
                            function_call=FunctionCall(
                                name=tc["function"]["name"],
                                arguments=tc["function"]["arguments"],
                            ),
                            extra={"function_id": tc.get("id", "1")},
                        ))
                if res:
                    yield res

    def _no_stream_oai_chat(
        self,
        oai_messages: List[dict],
        generate_cfg: dict,
    ) -> List[Message]:
        logger.debug(f"DeepSeek request cfg: {generate_cfg}")
        try:
            response = self._chat_complete_create(
                messages=oai_messages, stream=False, **generate_cfg
            )
        except OpenAIError as exc:
            raise ModelServiceError(exception=exc)

        msg = response.choices[0].message
        result: List[Message] = []
        reasoning = getattr(msg, "reasoning_content", None)
        if reasoning:
            result.append(Message(role=ASSISTANT, content="", reasoning_content=reasoning))
        if msg.content:
            result.append(Message(role=ASSISTANT, content=msg.content))
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            for tc in tool_calls:
                result.append(Message(
                    role=ASSISTANT,
                    content="",
                    function_call=FunctionCall(
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    ),
                    extra={"function_id": tc.id},
                ))
        if not result:
            result.append(Message(role=ASSISTANT, content=""))
        return result


def _resolve_api_key(cfg: Dict[str, Any]) -> str:
    key = cfg.get("api_key") or os.getenv("DEEPSEEK_API_KEY") or ""
    key = key.strip()
    if not key:
        raise ValueError(
            "DeepSeek API credential is not configured. "
            "Set the DEEPSEEK_API_KEY environment variable."
        )
    return key


def _resolve_base_url(cfg: Dict[str, Any]) -> str:
    url = (
        cfg.get("model_server")
        or cfg.get("base_url")
        or cfg.get("api_base")
        or os.getenv("DEEPSEEK_BASE_URL")
        or DEEPSEEK_DEFAULT_BASE_URL
    )
    return url.strip().rstrip("/")


def _convert_messages_to_oai(messages: List[Message]) -> List[dict]:
    messages = [format_as_text_message(msg, add_upload_info=False) for msg in messages]
    dicts = [msg.model_dump() for msg in messages]
    return _conv_qwen_agent_messages_to_oai(dicts)


def _conv_qwen_agent_messages_to_oai(messages: List[dict]) -> List[dict]:
    new_messages: List[dict] = []
    for msg in messages:
        if msg["role"] == ASSISTANT:
            if not new_messages or new_messages[-1]["role"] != ASSISTANT:
                new_messages.append({"role": ASSISTANT, "content": ""})
            if "content" in msg and msg["content"]:
                new_messages[-1]["content"] = msg["content"]
            if msg.get("reasoning_content"):
                new_messages[-1]["reasoning_content"] = msg["reasoning_content"]
            if msg.get("function_call"):
                if "tool_calls" not in new_messages[-1]:
                    new_messages[-1]["tool_calls"] = []
                new_messages[-1]["tool_calls"].append({
                    "id": msg.get("extra", {}).get("function_id", "1"),
                    "type": "function",
                    "function": {
                        "name": msg["function_call"]["name"],
                        "arguments": msg["function_call"]["arguments"],
                    },
                })
        elif msg["role"] == FUNCTION:
            new_msg = copy.deepcopy(msg)
            new_msg["role"] = "tool"
            new_msg.setdefault("tool_call_id", msg.get("extra", {}).get("function_id", "1"))
            if "content" not in new_msg or new_msg["content"] is None:
                new_msg["content"] = ""
            elif not isinstance(new_msg["content"], str):
                new_msg["content"] = str(new_msg["content"])
            new_messages.append(new_msg)
        else:
            if "content" not in msg or msg["content"] is None:
                msg["content"] = ""
            new_messages.append(msg)
    return new_messages


def _convert_functions_to_oai_tools(functions: List[dict]) -> List[dict]:
    tools: List[dict] = []
    for f in functions:
        if f.get("type") == "function":
            tools.append(f)
        else:
            params = f.get("parameters") or f.get("input_schema") or {}
            tools.append({
                "type": "function",
                "function": {
                    "name": f.get("name", ""),
                    "description": f.get("description", ""),
                    "parameters": _normalize_parameters(params),
                },
            })
    return tools


def _normalize_parameters(params: Any) -> dict:
    """Convert qwen-agent parameter arrays to JSON Schema object format."""
    if isinstance(params, dict) and params.get("type") == "object":
        return params
    if isinstance(params, list):
        properties: dict = {}
        required: list = []
        for item in params:
            name = item.get("name", "")
            if not name:
                continue
            prop: dict = {"type": _normalize_type(item.get("type"))}
            if item.get("description"):
                prop["description"] = item["description"]
            if item.get("enum"):
                prop["enum"] = item["enum"]
            properties[name] = prop
            if item.get("required"):
                required.append(name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }
    return {"type": "object", "properties": {}}


def _normalize_type(value: Any) -> str:
    if value in {"integer", "number", "boolean", "array", "object"}:
        return str(value)
    return "string"


def _clean_generate_cfg(generate_cfg: dict) -> dict:
    cfg = copy.deepcopy(generate_cfg)
    for key in (
        "lang", "max_input_tokens", "incremental_output",
        "skip_stopword_postproc", "parallel_function_calls",
        "function_choice", "thought_in_content", "cache_dir",
        "seed", "use_raw_api",
    ):
        cfg.pop(key, None)

    if "request_timeout" in cfg:
        cfg["timeout"] = cfg.pop("request_timeout")

    extra_params = ["top_k", "repetition_penalty"]
    if any(k in cfg for k in extra_params):
        extra_body = cfg.get("extra_body", {})
        if isinstance(extra_body, dict):
            extra_body = copy.deepcopy(extra_body)
        else:
            extra_body = {}
        for k in extra_params:
            if k in cfg:
                extra_body[k] = cfg.pop(k)
        cfg["extra_body"] = extra_body

    return cfg
