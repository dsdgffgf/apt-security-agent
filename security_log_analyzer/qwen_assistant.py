from __future__ import annotations

import importlib
from typing import Any

from .config import load_qwen_model_config
from .tools import TOOL_NAMES, run_local_tool_json


DEFENSE_TOOLS = [
    "read_log_file", "parse_log", "summarize_log",
    "extract_basic_patterns", "risk_hint", "format_evidence",
]
PENTEST_TOOLS = [
    "port_scan", "service_detect", "dir_enum",
    "web_fingerprint", "vuln_check", "pentest_report",
    "security_headers_check", "form_detect", "injection_probe",
]
ATTACK_TOOLS = [
    "payload_gen", "bypass_test", "info_gather", "attack_plan",
]
APT_TOOLS = [
    "osint_recon", "osint_tech_recon", "osint_social_recon",
    "se_phishing_gen", "se_conversation_gen",
    "apt_boundary_scan", "apt_exploit_plan",
    "apt_persistence_plan", "apt_log_clean",
    "apt_lateral_plan", "apt_privilege_plan",
    "apt_cross_plan", "apt_evasion_plan",
    "apt_report_gen",
    "apt_credential_attack", "apt_tunnel_establish",
    "apt_nmap_scan", "apt_smb_enum",
    "apt_web_poc", "apt_cve_scan", "apt_cve_verify",
    "apt_remote_exec", "apt_port_forward",
    "apt_nmap_nse_scan", "apt_redis_exploit", "apt_docker_exploit",
    "web_content_fetch",
    # Web User-Agent 枚举
    "web_user_agent_brute",
    "web_codename_brute",
    "web_login_brute",
    "hash_extract",
    "hash_crack",
    # Cross-phase tools from pentest modules
    "dir_enum", "web_fingerprint", "port_scan", "service_detect",
]

QWEN_TOOL_NAMES = TOOL_NAMES
SYSTEM_MESSAGE = """你是一个基于 Qwen-Agent Assistant 框架构建的日志安全分析智能体。
你运行在本地智能体应用中，Qwen-Agent Assistant 负责工具编排，实际语言理解、推理判断和报告生成由 DeepSeek API 完成。
你可以按需调用 read_log_file、parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence 等本地 Python 工具，但 Python 工具只提供辅助结果，不能替代最终安全判断。
不得要求用户在对话中提供 API Key、Token、密码等敏感信息，也不得输出、复述或推测任何密钥。
所有结论必须基于日志内容、工具返回结果或明确安全规则；证据不足时必须说明"当前证据不足，无法确认攻击是否成功"，并建议人工复核。"""


class QwenAgentUnavailableError(RuntimeError):
    pass


def build_qwen_llm_config(
    *,
    model: str | None = None,
    api_key: str | None = None,
    model_server: str | None = None,
    mode: str = "defense",
) -> dict[str, object]:
    return load_qwen_model_config(model=model, api_key=api_key, model_server=model_server, mode=mode)


def build_qwen_function_list(*, mode: str = "defense") -> list[str]:
    if mode == "pentest":
        return list(PENTEST_TOOLS)
    if mode == "attack":
        return list(ATTACK_TOOLS)
    if mode == "apt":
        return list(APT_TOOLS)
    return list(DEFENSE_TOOLS)


def _ensure_unique_function_ids_patched() -> None:
    """Monkey-patch FnCallAgent._run() 使用全局唯一的 function_id。

    Qwen Agent 默认 function_id 硬编码为 '1'，多渠道工具调用时会与
    DeepSeek API 的 tool_call_id 唯一性检查冲突。
    """
    import itertools
    import uuid

    try:
        fncall_mod = importlib.import_module("qwen_agent.agents.fncall_agent")
        fncall_agent_cls = getattr(fncall_mod, "FnCallAgent")
        _original_run = fncall_agent_cls._run
    except Exception:
        return  # 框架不可用时静默跳过

    MAX_TOOL_REPEAT = 7  # 同一工具最多调用次数，防止 LLM 死循环

    def _patched_run(self, messages, lang='en', **kwargs):
        messages = copy.deepcopy(messages)
        num_llm_calls_available = MAX_LLM_CALL_PER_RUN
        response = []
        _counter = itertools.count(1)
        _tool_call_counts: dict[str, int] = {}
        while True and num_llm_calls_available > 0:
            num_llm_calls_available -= 1
            extra_generate_cfg = {'lang': lang}
            if kwargs.get('seed') is not None:
                extra_generate_cfg['seed'] = kwargs['seed']
            output_stream = self._call_llm(
                messages=messages,
                functions=[func.function for func in self.function_map.values()],
                extra_generate_cfg=extra_generate_cfg)
            output: list = []
            for output in output_stream:
                if output:
                    yield response + output
            if output:
                response.extend(output)
                messages.extend(output)
                used_any_tool = False
                _tool_repeat_exceeded = False
                for out in output:
                    use_tool, tool_name, tool_args, _ = self._detect_tool(out)
                    if use_tool:
                        _tool_call_counts[tool_name] = _tool_call_counts.get(tool_name, 0) + 1
                        if _tool_call_counts[tool_name] >= MAX_TOOL_REPEAT:
                            _tool_repeat_exceeded = True
                            break  # 同一工具超限 → 跳出 inner loop
                        tool_result = self._call_tool(tool_name, tool_args, messages=messages, **kwargs)
                        fid = str(uuid.uuid4().hex[:8])  # ← 全局唯一 ID
                        fn_msg = Message(role=FUNCTION,
                                         name=tool_name,
                                         content=tool_result,
                                         extra={'function_id': fid})
                        # 同步更新 out 的 extra，确保转 OAI 时 tool_call id 一致
                        if out.extra is None:
                            out.extra = {}
                        out.extra['function_id'] = fid
                        messages.append(fn_msg)
                        response.append(fn_msg)
                        yield response
                        used_any_tool = True
                if not used_any_tool or _tool_repeat_exceeded:
                    break
        yield response

    fncall_agent_cls._run = _patched_run

    import copy
    from qwen_agent.llm.schema import FUNCTION, Message
    from qwen_agent.settings import MAX_LLM_CALL_PER_RUN


def create_qwen_security_assistant(
    *,
    llm_cfg: dict[str, Any] | None = None,
    system_message: str = SYSTEM_MESSAGE,
    mode: str = "defense",
    function_list: list[str] | None = None,
):
    try:
        importlib.import_module("security_log_analyzer.deepseek")
        _ensure_unique_function_ids_patched()  # 修复 tool_call_id 重复 bug
        agents_mod = importlib.import_module("qwen_agent.agents")
        tools_base_mod = importlib.import_module("qwen_agent.tools.base")
    except ImportError as exc:
        raise QwenAgentUnavailableError(
            "qwen-agent is not installed. Install it with: pip install qwen-agent"
        ) from exc

    _register_qwen_tools(tools_base_mod, mode=mode)
    assistant_cls = getattr(agents_mod, "Assistant")
    return assistant_cls(
        llm=llm_cfg or build_qwen_llm_config(mode=mode),
        system_message=system_message,
        function_list=function_list or build_qwen_function_list(mode=mode),
    )


def _register_qwen_tools(tools_base_mod, *, mode: str = "defense") -> None:
    base_tool_cls = getattr(tools_base_mod, "BaseTool")
    register_tool = getattr(tools_base_mod, "register_tool")

    tool_names = build_qwen_function_list(mode=mode)
    for tool_name in tool_names:
        sentinel = f"_{tool_name}_registered"
        if getattr(_register_qwen_tools, sentinel, False):
            continue
        tool_cls = _make_qwen_tool_class(tool_name, base_tool_cls)
        register_tool(tool_name)(tool_cls)
        setattr(_register_qwen_tools, sentinel, True)


def _make_qwen_tool_class(tool_name: str, base_tool_cls):
    if tool_name == "read_log_file":
        parameters = [
            {
                "name": "path",
                "type": "string",
                "description": "用户上传或指定的日志文件路径，不包含任何密钥或 Token。",
                "required": True,
            }
        ]
    elif tool_name == "format_evidence":
        parameters = [
            {
                "name": "evidence",
                "type": "array",
                "description": "需要整理并脱敏的日志证据行。",
                "required": True,
            },
            {
                "name": "limit",
                "type": "integer",
                "description": "最多保留的证据条数。",
                "required": False,
            },
        ]
    elif tool_name in {"parse_log", "summarize_log", "extract_basic_patterns", "risk_hint"}:
        parameters = [
            {
                "name": "log_input",
                "type": "string",
                "description": "用户提供的日志文本或日志文件路径。",
                "required": True,
            },
        ]
    elif tool_name == "port_scan":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 地址或域名", "required": True},
            {"name": "ports", "type": "array", "description": "要扫描的端口号列表，不传则扫描 100+ 常用端口", "required": False},
        ]
    elif tool_name == "service_detect":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 地址或域名", "required": True},
            {"name": "ports", "type": "array", "description": "要检测的端口号列表", "required": False},
        ]
    elif tool_name in {"dir_enum", "web_fingerprint", "info_gather"}:
        parameters = [
            {"name": "target", "type": "string", "description": "目标 URL、IP 或域名", "required": True},
        ]
    elif tool_name == "vuln_check":
        parameters = [
            {"name": "services", "type": "array", "description": "service_detect 返回的服务列表", "required": False},
            {"name": "fingerprint", "type": "object", "description": "web_fingerprint 返回的结果", "required": False},
        ]
    elif tool_name == "pentest_report":
        parameters = [
            {"name": "findings", "type": "object", "description": "所有渗透工具的汇总发现", "required": True},
            {"name": "target", "type": "string", "description": "测试目标", "required": False},
        ]
    elif tool_name == "payload_gen":
        parameters = [
            {"name": "attack_type", "type": "string", "description": "攻击类型: sqli / xss / cmd", "required": False},
            {"name": "count", "type": "integer", "description": "生成数量", "required": False},
        ]
    elif tool_name == "bypass_test":
        parameters = [
            {"name": "payload", "type": "string", "description": "原始 payload 字符串", "required": True},
            {"name": "target_encoding", "type": "string", "description": "绕过编码类型: url / double_url / unicode / hex / base64 / case_mix", "required": False},
        ]
    elif tool_name == "attack_plan":
        parameters = [
            {"name": "target_info", "type": "object", "description": "info_gather 或 port_scan 返回的目标信息", "required": False},
        ]
    elif tool_name == "security_headers_check":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 URL、IP 或域名", "required": True},
        ]
    elif tool_name == "form_detect":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 URL、IP 或域名", "required": True},
        ]
    elif tool_name == "injection_probe":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 URL、IP 或域名", "required": True},
            {"name": "param", "type": "string", "description": "指定要测试的参数名", "required": False},
        ]
    elif tool_name in {"osint_recon", "osint_tech_recon", "osint_social_recon"}:
        parameters = [
            {"name": "target", "type": "string", "description": "目标域名、IP 或组织名称", "required": True},
        ]
    elif tool_name == "se_phishing_gen":
        parameters = [
            {"name": "context", "type": "object", "description": "上下文信息，包含 target、organization、leader_name 等", "required": True},
        ]
    elif tool_name == "se_conversation_gen":
        parameters = [
            {"name": "context", "type": "object", "description": "上下文信息，包含 target、organization 等", "required": True},
        ]
    elif tool_name == "apt_boundary_scan":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
        ]
    elif tool_name == "apt_exploit_plan":
        parameters = [
            {"name": "scan_results", "type": "object", "description": "apt_boundary_scan 的返回结果", "required": True},
        ]
    elif tool_name == "apt_persistence_plan":
        parameters = [
            {"name": "target_info", "type": "object", "description": "目标信息，包含 target、os 等", "required": True},
        ]
    elif tool_name == "apt_log_clean":
        parameters = [
            {"name": "target_info", "type": "object", "description": "目标信息，包含 target、os 等", "required": True},
        ]
    elif tool_name == "apt_lateral_plan":
        parameters = [
            {"name": "state", "type": "object", "description": "当前 APT 状态，包含 targets、network_info 等", "required": True},
        ]
    elif tool_name == "apt_privilege_plan":
        parameters = [
            {"name": "state", "type": "object", "description": "当前 APT 状态，包含 current_level、target_info 等", "required": True},
        ]
    elif tool_name == "apt_cross_plan":
        parameters = [
            {"name": "state", "type": "object", "description": "当前 APT 状态，包含 target、apt_targets、via_target（跳板源）、blue_team_awareness 等", "required": True},
        ]
    elif tool_name == "apt_evasion_plan":
        parameters = [
            {"name": "state", "type": "object", "description": "当前 APT 状态，包含 blue_team_awareness、target 等", "required": True},
        ]
    elif tool_name == "apt_report_gen":
        parameters = [
            {"name": "state", "type": "object", "description": "当前 APT 状态，包含所有阶段结果", "required": True},
        ]
    elif tool_name == "apt_credential_attack":
        parameters = [
            {"name": "host", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "services", "type": "array", "description": "从 apt_boundary_scan/apt_nmap_scan 获取的服务列表 [{port, service, banner}]，不传则尝试常见端口", "required": False},
            {"name": "users", "type": "array", "description": "自定义用户名列表，不传使用内置常见用户字典", "required": False},
            {"name": "passwords", "type": "array", "description": "自定义密码列表，不传使用内置常见密码字典", "required": False},
            {"name": "max_threads", "type": "integer", "description": "每个服务最大并发线程数（默认5）", "required": False},
        ]
    elif tool_name == "apt_tunnel_establish":
        parameters = [
            {"name": "host", "type": "string", "description": "已控目标的 IP 或域名", "required": True},
            {"name": "username", "type": "string", "description": "通过爆破获得或已知的 SSH 用户名", "required": True},
            {"name": "password", "type": "string", "description": "SSH 密码", "required": True},
            {"name": "port", "type": "integer", "description": "SSH 端口（默认22）", "required": False},
            {"name": "local_bind_port", "type": "integer", "description": "本地 SOCKS5 代理端口（默认1080）", "required": False},
        ]
    elif tool_name == "apt_nmap_scan":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP、域名或网段（如 192.168.1.0/24）", "required": True},
            {"name": "ports", "type": "string", "description": "端口范围，如 '1-1000'、'22,80,443'（默认1-1000）", "required": False},
            {"name": "service_detect", "type": "boolean", "description": "是否进行服务版本识别（默认 true）", "required": False},
            {"name": "os_detect", "type": "boolean", "description": "是否进行 OS 检测（默认 false）", "required": False},
            {"name": "scripts", "type": "array", "description": "NSE 脚本列表，如 ['vuln', 'auth']", "required": False},
        ]
    elif tool_name == "apt_smb_enum":
        parameters = [
            {"name": "host", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "username", "type": "string", "description": "SMB 用户名（可选，不传则匿名枚举）", "required": False},
            {"name": "password", "type": "string", "description": "SMB 密码", "required": False},
        ]
    elif tool_name == "apt_web_poc":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "port", "type": "integer", "description": "Web 服务端口（默认 80）", "required": False},
            {"name": "https", "type": "boolean", "description": "是否使用 HTTPS（默认 false）", "required": False},
            {"name": "path", "type": "string", "description": "基础路径（默认 /）", "required": False},
            {"name": "params", "type": "object", "description": "测试参数字典，如 {\"id\": \"1\", \"page\": \"index\"}", "required": False},
        ]
    elif tool_name == "apt_cve_scan":
        parameters = [
            {"name": "services", "type": "array", "description": "从 apt_nmap_scan 获取的服务列表，每项含 service/product/version/port", "required": True},
        ]
    elif tool_name == "apt_cve_verify":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "cve_id", "type": "string", "description": "CVE 编号，如 CVE-2021-41773", "required": True},
            {"name": "port", "type": "integer", "description": "服务端口", "required": False},
            {"name": "https", "type": "boolean", "description": "是否使用 HTTPS（默认 false）", "required": False},
        ]
    elif tool_name == "apt_remote_exec":
        parameters = [
            {"name": "host", "type": "string", "description": "已控目标的 IP", "required": True},
            {"name": "username", "type": "string", "description": "SSH 用户名", "required": True},
            {"name": "password", "type": "string", "description": "SSH 密码", "required": True},
            {"name": "command", "type": "string", "description": "要执行的命令，如 'whoami; id; uname -a'", "required": True},
            {"name": "port", "type": "integer", "description": "SSH 端口（默认 22）", "required": False},
        ]
    elif tool_name == "apt_port_forward":
        parameters = [
            {"name": "host", "type": "string", "description": "已控目标的 IP", "required": True},
            {"name": "username", "type": "string", "description": "SSH 用户名", "required": True},
            {"name": "password", "type": "string", "description": "SSH 密码", "required": True},
            {"name": "remote_host", "type": "string", "description": "要映射的内网目标 IP", "required": True},
            {"name": "remote_port", "type": "integer", "description": "要映射的内网目标端口", "required": True},
            {"name": "ssh_port", "type": "integer", "description": "SSH 端口（默认 22）", "required": False},
            {"name": "local_port", "type": "integer", "description": "本地监听端口（0=自动选择）", "required": False},
        ]
    elif tool_name == "apt_nmap_nse_scan":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "ports", "type": "string", "description": "端口范围（默认全端口）", "required": False},
        ]
    elif tool_name == "apt_redis_exploit":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP", "required": True},
            {"name": "port", "type": "integer", "description": "Redis 端口（默认 6379）", "required": False},
            {"name": "ssh_public_key", "type": "string", "description": "SSH 公钥字符串（可选，用于写入 authorized_keys）", "required": False},
        ]
    elif tool_name == "apt_docker_exploit":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP", "required": True},
            {"name": "port", "type": "integer", "description": "Docker API 端口（默认 2375）", "required": False},
        ]
    elif tool_name == "web_content_fetch":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "port", "type": "integer", "description": "HTTP 端口（默认 80）", "required": False},
            {"name": "https", "type": "boolean", "description": "是否使用 HTTPS（默认 false）", "required": False},
            {"name": "path", "type": "string", "description": "访问路径（默认 /）", "required": False},
            {"name": "user_agent", "type": "string", "description": "自定义 User-Agent 头", "required": False},
        ]
    elif tool_name == "web_user_agent_brute":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "port", "type": "integer", "description": "HTTP 端口（默认 80）", "required": False},
            {"name": "https", "type": "boolean", "description": "是否使用 HTTPS（默认 false）", "required": False},
            {"name": "path", "type": "string", "description": "访问路径（默认 /）", "required": False},
        ]
    elif tool_name == "web_codename_brute":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "port", "type": "integer", "description": "HTTP 端口（默认 80）", "required": False},
            {"name": "wordlist", "type": "array", "description": "自定义 codename 列表（默认使用 A-Z+常见名称）", "required": False},
            {"name": "path", "type": "string", "description": "访问路径（默认 /）", "required": False},
        ]
    elif tool_name == "web_login_brute":
        parameters = [
            {"name": "target", "type": "string", "description": "目标 IP 或域名", "required": True},
            {"name": "port", "type": "integer", "description": "HTTP 端口（默认 80）", "required": False},
            {"name": "usernames", "type": "array", "description": "用户名/codename 列表（默认使用 'chris' 等已知用户）", "required": False},
            {"name": "passwords", "type": "array", "description": "密码字典（默认包含常见弱口令 + 'weak'）", "required": False},
            {"name": "https", "type": "boolean", "description": "是否使用 HTTPS（默认 false）", "required": False},
            {"name": "login_path", "type": "string", "description": "登录页面路径（默认 /login）", "required": False},
        ]
    elif tool_name == "hash_extract":
        parameters = [
            {"name": "content", "type": "string", "description": "包含 hash 的文本内容（如 shadow 文件、配置文件、数据库导出等）", "required": True},
        ]
    elif tool_name == "hash_crack":
        parameters = [
            {"name": "hashes", "type": "array", "description": "hash_extract 输出的 hash 列表，或包含 hash 的文本内容", "required": True},
        ]
    else:
        raise ValueError(f"Unsupported Qwen tool: {tool_name}")

    tool_parameters = parameters

    class LocalSecurityTool(base_tool_cls):
        name = tool_name
        description = _tool_description(tool_name)
        parameters = tool_parameters

        def call(self, params: str, **kwargs) -> str:
            return run_local_tool_json(tool_name, params)

    LocalSecurityTool.__name__ = f"{_camel_case(tool_name)}Tool"
    return LocalSecurityTool


def _tool_description(tool_name: str) -> str:
    descriptions = {
        "read_log_file": "读取用户上传或指定路径中的日志文件，返回原始日志文本。",
        "parse_log": "解析日志内容，将原始日志转换为结构化数据。",
        "summarize_log": "生成日志总数、时间范围、IP、账号、成功失败次数等基础统计信息。",
        "extract_basic_patterns": "提取多次失败登录、账号枚举、Web 攻击特征、异常状态码等基础异常模式。",
        "risk_hint": "根据基础规则给出 Python 风险参考，不能替代最终风险结论。",
        "format_evidence": "整理并脱敏关键日志证据，便于最终报告引用。",
        "port_scan": "对目标 IP 进行 TCP 端口扫描，默认扫描 100+ 常用端口，返回开放端口列表。",
        "service_detect": "连接目标开放端口获取 Banner 信息，识别服务名称和版本。",
        "dir_enum": "对目标 Web 服务进行常见路径和敏感文件枚举，返回可达路径及 HTTP 状态码。",
        "web_fingerprint": "获取目标 Web 服务的响应头，识别 Web 服务器、中间件、编程语言等技术栈。",
        "vuln_check": "基于服务版本和技术栈信息，匹配本地 CVE 规则库，发现已知漏洞。",
        "pentest_report": "汇总所有渗透测试发现，计算风险等级，生成结构化渗透测试报告和修复建议。",
        "payload_gen": "根据攻击类型（SQL 注入/XSS/命令注入）生成测试 payload 及混淆变体。",
        "bypass_test": "对给定 payload 进行多种编码绕过（URL编码/Unicode/Hex/Base64/大小写混写）。",
        "info_gather": "对目标进行基础信息收集，包括 DNS 解析、反向解析等 OSINT 信息。",
        "attack_plan": "基于目标信息构建 Kill Chain 攻击路径规划，列出各阶段可用工具。",
        "security_headers_check": "检查目标 Web 服务的 HTTP 安全头配置（HSTS/CSP/X-Frame-Options 等 6 项），评估缺失风险。",
        "form_detect": "枚举目标页面 HTML 表单，检测是否包含 CSRF Token 保护和密码字段。",
        "injection_probe": "向目标 Web 参数提交安全测试载荷，检测是否存在参数反射注入风险。",
        "osint_recon": "对目标进行基础 OSINT 信息收集：DNS 解析、子域名枚举、邮箱格式推断、泄露数据检测。",
        "osint_tech_recon": "识别目标技术栈：Web 框架、WAF 类型、CDN、服务版本及已知漏洞。",
        "osint_social_recon": "社工信息收集：组织架构、关键岗位人员、邮箱格式、社交账号暴露面。",
        "se_phishing_gen": "生成钓鱼邮件（仿真）：支持领导冒充/IT通知/会议附件等场景，按目标角色差异化生成，贴合中文行文习惯。",
        "se_conversation_gen": "生成社工话术脚本（仿真）：IT 支持、外包商、HR 等场景的四步话术。",
        "apt_boundary_scan": "边界综合探测：端口扫描 + 服务识别 + VPN/邮件网关 + 防火墙品牌检测。",
        "apt_exploit_plan": "基于边界扫描结果规划突破方案：CVE 利用、弱口令、社工入口等。",
        "apt_persistence_plan": "持久化方案规划：WebShell、定时任务、注册表启动、SOCKS 隧道、C2 通道。",
        "apt_log_clean": "日志清理策略：按系统类型规划日志清理方案，规避监控。",
        "apt_lateral_plan": "横向移动路径规划：内网拓扑、跳板路线、凭证窃取目标、域控路径。",
        "apt_privilege_plan": "权限提升方案：内核漏洞、SUDO 配置错误、服务权限漏洞、域 ACL 滥用。",
        "apt_cross_plan": "跨目标攻击规划（供应链跳板）：利用已控跳板攻击下游目标，支持指定跳板源和攻击手段，信任关系利用，溯源干扰。",
        "apt_evasion_plan": "绕过与对抗方案：流量加密、分时段操作、白签名利用、内存执行、告警规避。",
        "apt_report_gen": "生成完整 APT 攻击模拟报告：攻击链重构、脆弱性总结、加固建议。",
        "apt_credential_attack": "对目标开放服务执行弱口令爆破（真实攻击），支持 SSH/FTP/MySQL/Redis/SMB/Telnet/HTTP。内置常见用户和密码字典，多线程并发。返回成功爆破的凭证。",
        "apt_tunnel_establish": "在成功获得 SSH 凭证后，建立 SSH SOCKS5 动态隧道代理到目标，返回本地代理地址 (127.0.0.1:1080)，用于后续内网扫描。",
        "apt_nmap_scan": "使用 nmap 对目标进行深度扫描，支持服务版本识别、OS 检测、NSE 漏洞脚本。比内置的 apt_boundary_scan 更全面，推荐优先使用。",
        "apt_smb_enum": "使用 impacket 枚举目标的 SMB 共享目录、用户和操作系统信息，支持匿名和凭证两种模式。",
        "apt_web_poc": "对 Web 服务执行真实漏洞 PoC 检测：SQL 注入（error-based/boolean-based/union）、LFI（/etc/passwd）、XSS 反射。发送 payload 并分析响应确认漏洞。",
        "apt_cve_scan": "基于 nmap 扫描结果（服务名+产品名+版本号）匹配内置真实 CVE 数据库（CVE-2024-6387 OpenSSH regreSSHion、CVE-2021-41773 Apache 路径遍历等 15+ CVE）。",
        "apt_cve_verify": "对指定 CVE 执行真实 PoC 验证。验证目标是否真实存在漏洞，支持 CVE-2021-41773、CVE-2021-42013 等。发送无害 payload 并检测响应。",
        "apt_remote_exec": "通过 SSH 在已控目标上执行系统命令。需要有效的 SSH 凭证。返回命令的 stdout/stderr/exit_code。用于信息收集、内网探测等。",
        "apt_port_forward": "SSH 端口转发 — 将已控目标内网的端口映射到本地，突破网络隔离。例如将内网 10.0.0.100:3389 (RDP) 映射到本地 127.0.0.1:20001。",
        "apt_nmap_nse_scan": "nmap NSE 漏洞扫描 — 使用 30+ 精选脚本自动检测 ms17-010(EternalBlue)、Heartbleed、Shellshock、vsftpd后门、Redis未授权、MySQL空密码、CVE-2021-41773 等。覆盖最广的自动漏洞发现方式。",
        "apt_redis_exploit": "Redis 未授权访问利用 — 检测是否需要认证，若不需要则可写入 SSH 公钥直接获得 root Shell。也支持弱口令爆破。",
        "apt_docker_exploit": "Docker Remote API 未授权利用 — 检测 Docker Daemon API (2375/2376) 是否开放，若开放可列举所有容器和镜像，创建特权容器逃逸到宿主机。",
        "web_content_fetch": "获取 Web 页面内容（HTML 源码和响应头）。访问目标 HTTP 页面并返回完整响应，用于分析网页中可能存在的认证提示、隐藏信息、留言板、配置暴露等。CTF/渗透场景中优先使用这个工具查看网页内容，而非盲扫漏洞。",
        "web_user_agent_brute": "遍历 A-Z 共 26 个单字母 User-Agent 探测目标 Web 服务是否存在基于 User-Agent 的访问控制机制。适用于 Agent ID / codename 类型的认证绕过场景。依次发送每个字母作为 UA，对比各响应与基准的差异，发现异常认证提示或警告信息。",
        "web_codename_brute": "使用自定义 codename 字典作为 User-Agent 批量探测 Web 认证机制。与 web_user_agent_brute（固定 A-Z 单字母）不同，本工具接受任意 codename 列表（如 ['chris', 'admin', 'agent']），适用于已知部分 codename 后进一步枚举更多有效身份。自动检测哪些 codename 返回了不同的页面内容。",
        "web_login_brute": "Web 登录爆破工具。专门用于 HTTP Basic Auth、表单登录和 UA+密码组合认证的定向爆破。与 apt_credential_attack（侧重 SSH/FTP/SMB）不同，本工具只针对 Web 认证。支持三种方式：(1)Authorization Basic 头 (2)POST username+password 表单 (3)User-Agent + 密码参数组合。适用场景：发现有效用户名/codename 后批量测试弱口令。",
        "hash_extract": "从文本内容中提取密码 hash（MD5/SHA1/SHA256/SHA512/NTLM/Linux shadow）。自动识别常见 hash 格式，返回 hash 类型和值列表。适用于分析从目标获取的 /etc/shadow、配置文件、数据库导出等文件中的密码 hash。",
        "hash_crack": "对提取的 hash 执行密码破解。自动识别 hash 类型并使用内置字典 + 常见变换规则尝试破解。支持 MD5/SHA1/SHA256/SHA512/NTLM 的字典攻击。如果系统安装了 John the Ripper，也会自动调用进行 shadow 格式破解。",
    }
    return descriptions[tool_name]


def _camel_case(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("_"))
