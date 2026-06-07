from __future__ import annotations

import json
import re
from typing import Any, Callable

from .apt_core import run_apt_simulation
from .pentest_tools import WARNING_TEXT, validate_target
from .qwen_assistant import create_qwen_security_assistant
from .standards import StandardsAssessment, format_standards_brief, format_standards_lines


SECURITY_AGENT_SYSTEM_MESSAGE = """你是一个日志安全分析智能体。
你的任务是基于用户提供的日志判断是否存在异常、攻击迹象、误报可能和风险等级。
你必须优先使用本地工具进行分析，不要只凭猜测直接下结论。
可用工具包括 read_log_file、parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence。
如果输入是日志文件路径，请先调用 read_log_file 读取，再依次调用 parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence。
如果输入是日志文本，请直接对文本调用 parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence。
你还必须结合行业标准层（OWASP / MITRE ATT&CK / NIST）解释最终判断。
最后只输出严格 JSON，不要输出额外解释、Markdown 或代码块之外的内容。JSON 字段要求如下：
{
  "selected_tools": ["parse_log"],
  "analysis_path": ["先读取日志", "再解析日志", "最后综合判断"],
  "has_anomaly": true,
  "suspected_attack": true,
  "attack_types": ["暴力破解尝试"],
  "attack_success_assessment": "疑似攻击成功",
  "false_positive_assessment": "误报可能较低",
  "evidence_sufficiency": "证据较充分",
  "confidence": "高置信度",
  "standards_summary": "OWASP / MITRE ATT&CK / NIST 标准依据摘要",
  "standards_references": ["OWASP A07 Identification and Authentication Failures"],
  "standards_consistency": "一致",
  "final_risk": {
    "score": 90,
    "level": "严重",
    "reasons": ["..."]
  },
  "score_adjusted": false,
  "adjustment_reason": "未调整",
  "summary": "一句话结论"
}
"""


class SecurityAgentError(RuntimeError):
    pass


# ── pentest mode ─────────────────────────────────────────

PENTEST_SYSTEM_MESSAGE = """你是一个自动化渗透测试智能体。
你的任务是对用户指定的目标进行受控安全测试，发现开放端口、服务版本、Web 路径、技术栈、已知漏洞、HTTP 安全配置缺陷和注入风险。
你必须谨慎使用网络工具，只对用户明确授权测试的目标进行操作。
可用工具包括 port_scan、service_detect、dir_enum、web_fingerprint、vuln_check、security_headers_check、form_detect、injection_probe、pentest_report。
推荐工作流程：
1. 先用 port_scan 扫描目标 100+ 常用端口
2. 对发现的开放端口调用 service_detect 获取服务版本
3. 如果有 Web 服务（80/443/8080/8443），调用 dir_enum 枚举路径，web_fingerprint 识别技术栈
4. 对 Web 服务调用 security_headers_check 检查安全头配置
5. 对 Web 服务调用 form_detect 检测表单及 CSRF 保护
6. 如有表单参数，调用 injection_probe 探测参数反射注入风险
7. 调用 vuln_check 匹配已知 CVE
8. 最后调用 pentest_report 汇总所有发现
每次工具调用后，先看结果再决定下一步，不要盲目连续调用。
最后只输出严格 JSON 渗透测试报告。JSON 字段要求如下：
{
  "selected_tools": ["port_scan", "service_detect"],
  "analysis_path": ["先扫描端口", "再识别服务", "Web安全检查", "漏洞匹配", "最终报告"],
  "target": "目标地址",
  "open_ports_summary": {"total": 3, "ports": [22, 80, 443]},
  "services_detected": [{"port": 22, "service": "OpenSSH", "version": "7.4"}],
  "web_tech": ["Apache", "PHP"],
  "discovered_dirs": [{"path": "/admin", "status": 200}],
  "security_headers": {"missing": [], "risk_level": "中危"},
  "form_analysis": {"total_forms": 2, "csrf_protected": 1, "risk": "中"},
  "injection_findings": {"reflected_params": [], "risk": "低危"},
  "vulnerabilities": [{"cve": "CVE-2018-15473", "severity": "high", "service": "OpenSSH"}],
  "risk_level": "高危",
  "recommendations": ["建议升级 OpenSSH 到最新版本"],
  "summary": "渗透测试一句话结论"
}
"""


def run_pentest_agent(
    *,
    target: str,
    assistant_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    err = validate_target(target)
    if err:
        raise SecurityAgentError(f"目标校验失败: {err}")

    try:
        print(f"[!] {WARNING_TEXT}")
    except UnicodeEncodeError:
        safe_str = WARNING_TEXT.encode("gbk", errors="replace").decode("gbk")
        print(f"[!] {safe_str}")

    assistant = (assistant_factory or _default_pentest_factory)()
    prompt = _build_pentest_prompt(target)
    responses = assistant.run_nonstream([{"role": "user", "content": prompt}])
    final_text = _collect_final_assistant_text(responses)
    if not final_text.strip():
        raise SecurityAgentError("Pentest agent returned an empty response.")

    payload = _extract_json_payload(final_text)
    payload["_raw_response"] = final_text
    return payload


def _build_pentest_prompt(target: str) -> str:
    return (
        f"渗透测试目标：{target}\n\n"
        "请按照标准渗透测试流程对目标进行分析：\n"
        "1. port_scan 扫描端口\n"
        "2. service_detect 识别服务\n"
        "3. 如有 Web 服务则 dir_enum 和 web_fingerprint\n"
        "4. vuln_check 匹配漏洞\n"
        "5. pentest_report 生成报告\n\n"
        "最终输出严格 JSON，字段必须包含 selected_tools、analysis_path、target、"
        "open_ports_summary、services_detected、web_tech、discovered_dirs、"
        "vulnerabilities、risk_level、recommendations、summary。\n"
    )


def _default_pentest_factory():
    return create_qwen_security_assistant(
        system_message=PENTEST_SYSTEM_MESSAGE, mode="pentest"
    )


# ── attack mode ───────────────────────────────────────────

ATTACK_SYSTEM_MESSAGE = """你是一个攻击模拟研究智能体，仅用于红蓝对抗和安全研究环境。
你的任务是基于目标信息生成攻击 payload、测试防御绕过效果、进行 OSINT 信息收集、构建攻击路径规划。
你只能对用户指定的研究目标进行操作，不得对未经授权的系统发起任何操作。
可用工具包括 payload_gen、bypass_test、info_gather、attack_plan。
工作流程：
1. 如有目标，调用 info_gather 收集基本信息
2. 根据目标类型调用 payload_gen 生成针对性测试载荷
3. 对需要绕过测试的 payload 调用 bypass_test 生成编码变体
4. 最后调用 attack_plan 构建完整 Kill Chain 攻击路径
所有工具只用于安全研究和授权测试，严禁用于未授权攻击。
最后只输出严格 JSON。JSON 字段要求如下：
{
  "selected_tools": ["info_gather", "payload_gen"],
  "analysis_path": ["信息收集", "payload 生成", "绕过测试", "攻击路径规划"],
  "target_info": {"ip": "x.x.x.x", "hostname": "..."},
  "payloads": [{"type": "sqli", "payload": "' OR '1'='1", "encoding": "plain"}],
  "bypass_variants": {"original": "...", "variants": {"url": "%27...", "unicode": "..."}},
  "kill_chain": [
    {"phase": "reconnaissance", "description": "...", "tools": ["info_gather"]}
  ],
  "risk_note": "此 payload 仅用于授权测试环境",
  "summary": "攻击模拟一句话结论"
}
"""


def run_attack_agent(
    *,
    target: str | None = None,
    assistant_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    print(f"[!!] {WARNING_TEXT}")
    print("[!!] 攻击模拟模式仅限隔离研究环境使用！严禁对未授权目标使用！")

    assistant = (assistant_factory or _default_attack_factory)()
    prompt = _build_attack_prompt(target)
    responses = assistant.run_nonstream([{"role": "user", "content": prompt}])
    final_text = _collect_final_assistant_text(responses)
    if not final_text.strip():
        raise SecurityAgentError("Attack agent returned an empty response.")

    payload = _extract_json_payload(final_text)
    payload["_raw_response"] = final_text
    return payload


def _build_attack_prompt(target: str | None = None) -> str:
    target_line = f"研究目标：{target}\n\n" if target else "研究目标：无特定目标，请生成通用攻击研究内容。\n\n"
    return (
        f"{target_line}"
        "请根据指定模式完成以下任务：\n"
        "1. 如有目标则 info_gather 收集信息\n"
        "2. payload_gen 生成测试载荷（可选择 sqli/xss/cmd 类型）\n"
        "3. bypass_test 测试绕过变体\n"
        "4. attack_plan 构建攻击路径\n\n"
        "最终输出严格 JSON，字段必须包含 selected_tools、analysis_path、target_info、"
        "payloads、bypass_variants、kill_chain、risk_note、summary。\n"
    )


def _default_attack_factory():
    return create_qwen_security_assistant(
        system_message=ATTACK_SYSTEM_MESSAGE, mode="attack"
    )


# ── apt mode ──────────────────────────────────────────────

def run_apt_agent(
    *,
    target: str = "",
    vector: str = "firewall_breach",
    cross_target: str = "",
    assistant_factory: Callable[[str, list[str]], Any] | None = None,
    resume: bool = False,
    c2_host: str = "",
    c2_port: int = 8080,
) -> dict[str, Any]:
    """APT 攻击模拟主入口 — 单目标单向量，supply_chain 支持跨目标"""
    from .apt_tools import WARNING_TEXT as APT_WARNING
    from .config import C2_HOST, C2_PORT
    print(f"[!] {APT_WARNING}")
    print(f"[!] 攻击向量: {vector}")
    if cross_target:
        print(f"[!] 跳板攻击: {target} -> {cross_target}")
    if vector == "phishing":
        _c2_h = c2_host or C2_HOST
        _c2_p = c2_port or C2_PORT
        print(f"[!] C2 监听器: http://{_c2_h}:{_c2_p}")
    print("[!] 此模式执行真实 DNS 解析/端口扫描/技术识别和社工内容生成！仅用于授权测试！")

    if not target:
        raise SecurityAgentError("必须指定目标。")

    sim_target: dict[str, Any] = {"id": "target_0", "host": target, "vector": vector}
    if cross_target and vector == "supply_chain":
        sim_target["cross_host"] = cross_target
        sim_target["cross_id"] = "target_cross"
    if vector == "phishing":
        _c2_h = c2_host or C2_HOST
        _c2_p = c2_port or C2_PORT
        from .c2_listener import get_local_ip
        _local_ip = get_local_ip()
        sim_target["c2_url"] = f"http://{_local_ip}:{_c2_p}/capture"
        sim_target["c2_payload_url"] = f"http://{_local_ip}:{_c2_p}/payload.ps1"

    return run_apt_simulation(sim_target, assistant_factory=assistant_factory, resume=resume)


# ── original defense entry (unchanged) ────────────────────

def run_security_agent_analysis(
    *,
    log_input: str,
    source: str | None = None,
    is_path: bool = False,
    standards: StandardsAssessment | None = None,
    assistant_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    assistant = (assistant_factory or _default_assistant_factory)()
    prompt = build_security_agent_prompt(log_input, source=source, is_path=is_path, standards=standards)
    responses = assistant.run_nonstream([{"role": "user", "content": prompt}])
    final_text = _collect_final_assistant_text(responses)
    if not final_text.strip():
        raise SecurityAgentError("Qwen agent returned an empty response.")

    payload = _extract_json_payload(final_text)
    payload["_raw_response"] = final_text
    return payload


def build_security_agent_prompt(
    log_input: str,
    *,
    source: str | None = None,
    is_path: bool = False,
    standards: StandardsAssessment | None = None,
) -> str:
    source_text = source or ("日志文件" if is_path else "用户输入")
    standards_text = format_standards_brief(standards)
    standards_lines = "\n".join(format_standards_lines(standards))

    if is_path:
        return (
            f"日志来源：{source_text}\n"
            f"日志文件路径：{log_input}\n\n"
            f"行业标准层摘要：{standards_text}\n"
            f"行业标准层明细：\n{standards_lines}\n\n"
            "请先读取日志文件，再依次调用 parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence 等工具完成分析。\n"
            "最终输出严格 JSON，字段必须包含 selected_tools、analysis_path、has_anomaly、suspected_attack、attack_types、attack_success_assessment、false_positive_assessment、evidence_sufficiency、confidence、standards_summary、standards_references、standards_consistency、final_risk、score_adjusted、adjustment_reason、summary。\n"
        )

    return (
        f"日志来源：{source_text}\n\n"
        f"行业标准层摘要：{standards_text}\n"
        f"行业标准层明细：\n{standards_lines}\n\n"
        "下面是原始日志文本，请直接调用 parse_log、summarize_log、extract_basic_patterns、risk_hint、format_evidence 等工具完成分析。\n\n"
        f"```log\n{log_input}\n```\n\n"
        "分析完成后，只输出严格 JSON，字段必须包含 selected_tools、analysis_path、has_anomaly、suspected_attack、attack_types、attack_success_assessment、false_positive_assessment、evidence_sufficiency、confidence、standards_summary、standards_references、standards_consistency、final_risk、score_adjusted、adjustment_reason、summary。\n"
    )


def _default_assistant_factory():
    return create_qwen_security_assistant(system_message=SECURITY_AGENT_SYSTEM_MESSAGE)


def _collect_final_assistant_text(responses: Any) -> str:
    items = list(responses or [])
    assistant_texts: list[str] = []
    for item in items:
        if _get_value(item, "role") != "assistant":
            continue
        text = _message_text(_get_value(item, "content"))
        if text:
            assistant_texts.append(text)
    if assistant_texts:
        return assistant_texts[-1]
    if items:
        return _message_text(_get_value(items[-1], "content"))
    return ""


def _extract_json_payload(text: str) -> dict[str, Any]:
    # 多种策略提取 JSON：代码块 → 最外层 {} → 裸文本
    candidates: list[str] = []

    # 策略 1: 提取所有 ```json 或 ``` 代码块
    fence_pattern = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.I)
    for m in fence_pattern.finditer(text):
        candidates.append(m.group(1).strip())

    # 策略 2: 原始文本（跳过代码块标记）
    clean = re.sub(r"```(?:json)?\s*|```", "", text).strip()
    candidates.append(clean)

    for candidate in candidates:
        if not candidate:
            continue
        # 找到最外层的完整 JSON 对象
        start = candidate.find("{")
        if start == -1:
            continue
        # 从 start 开始，找匹配的闭合 }
        depth = 0
        end = -1
        for i in range(start, len(candidate)):
            ch = candidate[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            continue
        json_str = candidate[start : end + 1]
        try:
            payload = json.loads(json_str)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise SecurityAgentError(f"Failed to parse agent JSON output: {text[:400]}")


def _get_value(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _message_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                if item.get("text") is not None:
                    parts.append(str(item["text"]))
                elif item.get("thinking") is not None:
                    parts.append(str(item["thinking"]))
                elif item.get("content") is not None:
                    parts.append(_message_text(item["content"]))
            else:
                parts.append(str(item))
        return "".join(parts)
    if isinstance(value, dict):
        if value.get("text") is not None:
            return str(value["text"])
        if value.get("thinking") is not None:
            return str(value["thinking"])
        if value.get("content") is not None:
            return _message_text(value["content"])
    return str(value)
