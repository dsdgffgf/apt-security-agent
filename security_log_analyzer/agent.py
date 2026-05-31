from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .agentic import SecurityAgentError, run_security_agent_analysis
from .detectors import (
    detect_abnormal_ip,
    detect_bruteforce,
    detect_success_after_failures,
    detect_web_attack,
)
from .models import AgentJudgment, FailedLoginStats, Finding, RiskResult, SecurityAnalysis, StandardsAssessment
from .parser import parse_log
from .standards import build_standards_assessment, format_standard_reference
from .stats import count_failed_login
from .tools import extract_basic_patterns, read_log_file, risk_hint, summarize_log


LOGIN_LOG_TYPES = {"ssh_login", "system_login", "cloud_login"}
SECURITY_DEVICE_LOG_TYPES = {"firewall", "waf_alert", "ids_ips_alert"}
ATTACK_TYPE_LABELS = {
    "bruteforce": "暴力破解尝试",
    "success_after_failures": "多次失败后成功登录",
    "account_enumeration": "账号枚举",
    "web_scan": "Web 扫描",
    "sql_injection": "SQL 注入",
    "xss": "XSS",
    "directory_traversal": "目录遍历",
    "command_injection": "命令注入",
    "sensitive_file_access": "敏感文件访问",
    "suspicious_external_ip": "可疑外部 IP",
}


def analyze_security_logs(
    log_input: str | Path | None,
    *,
    source: str | None = None,
    qwen_agent_used: bool = False,
    qwen_agent_factory: Callable[[], Any] | None = None,
) -> SecurityAnalysis:
    if log_input is None:
        raise ValueError("log_input is required.")

    selected_tools: list[str] = []
    log_text, file_source = _resolve_log_input(log_input)
    if file_source:
        selected_tools.append("read_log_file")

    selected_tools.append("parse_log")
    parse_result = parse_log(log_text)
    source_label = source or file_source or parse_result.source or (
        "日志文本" if isinstance(log_text, str) and "\n" in log_text else str(log_input)
    )

    selected_tools.append("summarize_log")
    summary = summarize_log(parse_result.records)

    failed_login_stats: FailedLoginStats | None = None
    tool_findings: dict[str, list[Finding]] = {}

    record_types = {record.log_type for record in parse_result.records}
    needs_login = _needs_login_tools(parse_result.log_type, record_types)
    needs_web = _needs_web_tools(parse_result.log_type, record_types)
    needs_security_device = _needs_security_device_tools(parse_result.log_type, record_types)

    if needs_login:
        failed_login_stats = count_failed_login(parse_result.records)
        brute_findings = detect_bruteforce(parse_result.records)
        tool_findings["detect_bruteforce"] = brute_findings
        success_findings = detect_success_after_failures(parse_result.records)
        tool_findings["detect_success_after_failures"] = success_findings

    if needs_web:
        web_findings = detect_web_attack(parse_result.records)
        tool_findings["detect_web_attack"] = web_findings

    if needs_login or needs_web or needs_security_device or parse_result.log_type in {"unknown", "mixed", "api_access", "iot_event"}:
        abnormal_findings = detect_abnormal_ip(parse_result.records)
        tool_findings["detect_abnormal_ip"] = abnormal_findings

    selected_tools.append("extract_basic_patterns")
    findings = extract_basic_patterns(parse_result.records)
    tool_findings["extract_basic_patterns"] = findings

    selected_tools.append("risk_hint")
    tool_risk = risk_hint(findings, summary)
    standards = build_standards_assessment(findings, log_type=parse_result.log_type, summary=summary)
    judgment = _build_agent_judgment(
        log_type=parse_result.log_type,
        findings=findings,
        tool_risk=tool_risk,
        selected_tools=selected_tools,
        standards=standards,
    )

    agent_output: dict[str, Any] = {}
    agent_response: str | None = None
    if qwen_agent_used:
        try:
            agent_output = run_security_agent_analysis(
                log_input=file_source or log_text,
                source=source_label,
                is_path=bool(file_source),
                standards=standards,
                assistant_factory=qwen_agent_factory,
            )
            agent_response = str(agent_output.pop("_raw_response", "") or "") or None
            judgment = _merge_agent_judgment(judgment, agent_output, standards=standards)
        except Exception as exc:
            raise SecurityAgentError(f"Qwen agent analysis failed: {exc}") from exc

    if agent_output:
        selected_tools = _merge_str_lists(selected_tools, _coerce_str_list(agent_output.get("selected_tools")))

    return SecurityAnalysis(
        parse_result=parse_result,
        summary=summary,
        findings=findings,
        selected_tools=selected_tools,
        tool_risk=tool_risk,
        judgment=judgment,
        failed_login_stats=failed_login_stats,
        source=source_label,
        standards=standards,
        tool_findings=tool_findings,
        qwen_agent_used=qwen_agent_used,
        agent_response=agent_response,
        agent_output=agent_output,
    )


def _resolve_log_input(log_input: str | Path) -> tuple[str, str | None]:
    if isinstance(log_input, Path):
        return read_log_file(log_input), str(log_input)

    if "\n" not in log_input and "\r" not in log_input:
        possible_path = Path(log_input)
        if possible_path.exists():
            return read_log_file(possible_path), str(possible_path)

    return log_input, None


def _needs_login_tools(log_type: str, record_types: set[str]) -> bool:
    return log_type in LOGIN_LOG_TYPES or log_type == "mixed" or bool(record_types & LOGIN_LOG_TYPES)


def _needs_web_tools(log_type: str, record_types: set[str]) -> bool:
    return log_type in {"web_access", "mixed"} or "web_access" in record_types


def _needs_security_device_tools(log_type: str, record_types: set[str]) -> bool:
    return log_type in SECURITY_DEVICE_LOG_TYPES or bool(record_types & SECURITY_DEVICE_LOG_TYPES)


def _build_agent_judgment(
    *,
    log_type: str,
    findings: list[Finding],
    tool_risk: RiskResult,
    selected_tools: list[str],
    standards: StandardsAssessment | None,
) -> AgentJudgment:
    attack_types = _attack_types(findings)
    success_assessment = _attack_success_assessment(findings)
    false_positive_assessment = _false_positive_assessment(findings, success_assessment)
    evidence_sufficiency = _evidence_sufficiency(findings, success_assessment)
    base_final_risk, adjusted, adjustment_reason = _final_risk(tool_risk, findings, success_assessment)
    final_risk, standards_adjusted, standards_reason = _apply_standards_floor(base_final_risk, standards)
    confidence = _confidence(findings, success_assessment, evidence_sufficiency, adjusted or standards_adjusted)

    if standards_adjusted:
        adjusted = True
        adjustment_reason = f"{adjustment_reason}；{standards_reason}"

    standards_summary = standards.summary if standards else ""
    standards_references = [format_standard_reference(reference) for reference in standards.references] if standards else []
    standards_consistency = "已对照行业标准层" if standards else "未记录行业标准层"

    return AgentJudgment(
        has_anomaly=bool(findings),
        suspected_attack=bool(attack_types),
        attack_types=attack_types,
        attack_success_assessment=success_assessment,
        false_positive_assessment=false_positive_assessment,
        evidence_sufficiency=evidence_sufficiency,
        confidence=confidence,
        tool_risk=tool_risk,
        final_risk=final_risk,
        score_adjusted=adjusted,
        adjustment_reason=adjustment_reason,
        standards_summary=standards_summary,
        standards_references=standards_references,
        standards_consistency=standards_consistency,
        standards_risk=standards.risk if standards else None,
        analysis_path=_analysis_path(log_type, selected_tools, standards),
    )


def _attack_types(findings: list[Finding]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        label = ATTACK_TYPE_LABELS.get(finding.kind)
        if not label or label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def _attack_success_assessment(findings: list[Finding]) -> str:
    if not findings:
        return "未发现攻击"
    if any(finding.kind == "success_after_failures" for finding in findings):
        return "疑似攻击成功"
    if any(
        finding.kind == "sensitive_file_access" and finding.details.get("success") is True
        for finding in findings
    ):
        return "疑似攻击成功"
    if any(
        finding.kind == "command_injection" and finding.details.get("success") is True
        for finding in findings
    ):
        return "证据不足，无法判断是否成功"
    return "疑似攻击尝试"


def _false_positive_assessment(findings: list[Finding], success_assessment: str) -> str:
    web_findings = [
        finding
        for finding in findings
        if finding.kind in {"sql_injection", "xss", "directory_traversal", "command_injection", "sensitive_file_access"}
    ]
    if not findings:
        return "当前未发现明显异常，仍建议结合更多日志持续观察。"
    if web_findings and all(_is_failed_web_finding(finding) for finding in web_findings):
        return "存在误报可能：Web 攻击特征请求均返回 404 或失败状态码，需要结合服务端日志复核。"
    if success_assessment == "疑似攻击成功":
        return "误报可能较低，但仍需结合主机状态和账号操作记录复核。"
    return "存在一定误报可能，需要结合上下文、资产暴露面和后续日志复核。"


def _evidence_sufficiency(findings: list[Finding], success_assessment: str) -> str:
    if not findings:
        return "当前日志未提供异常证据。"
    if success_assessment == "疑似攻击成功":
        return "证据较充分，可支持疑似攻击成功的判断。"
    if all(finding.start_time is None and finding.end_time is None for finding in findings):
        return "证据存在缺口：部分异常缺少时间字段，需要人工复核。"
    return "证据可支持疑似攻击尝试判断，但不足以确认成功。"


def _final_risk(
    tool_risk: RiskResult,
    findings: list[Finding],
    success_assessment: str,
) -> tuple[RiskResult, bool, str]:
    web_findings = [
        finding
        for finding in findings
        if finding.kind in {"sql_injection", "xss", "directory_traversal", "command_injection", "sensitive_file_access"}
    ]
    success_after_high_privilege = any(
        finding.kind == "success_after_failures" and finding.details.get("high_risk_account")
        for finding in findings
    )

    if success_after_high_privilege and tool_risk.score < 85:
        reason = "发现高权限账号多次失败后成功登录，风险需要上调。"
        final_score = 85
        return (
            RiskResult(score=final_score, level=_score_to_level(final_score), reasons=[*tool_risk.reasons, reason]),
            True,
            reason,
        )

    if web_findings and all(_is_failed_web_finding(finding) for finding in web_findings) and tool_risk.score > 60:
        reason = "Web 攻击特征命中，但相关请求状态码均为 404 或失败，综合判断下调为攻击尝试风险。"
        final_score = 60
        return (
            RiskResult(score=final_score, level=_score_to_level(final_score), reasons=[*tool_risk.reasons, reason]),
            True,
            reason,
        )

    if success_assessment == "疑似攻击成功" and tool_risk.score < 81:
        reason = "日志存在疑似成功证据，风险需要上调。"
        final_score = 81
        return (
            RiskResult(score=final_score, level=_score_to_level(final_score), reasons=[*tool_risk.reasons, reason]),
            True,
            reason,
        )

    return tool_risk, False, "未调整 Python 风险提示。"


def _apply_standards_floor(
    risk: RiskResult,
    standards: StandardsAssessment | None,
) -> tuple[RiskResult, bool, str]:
    if standards is None:
        return risk, False, "未记录行业标准层。"
    if risk.score >= standards.risk.score:
        return risk, False, f"行业标准层参考：{standards.summary}"

    final_score = standards.risk.score
    reasons = _merge_reason_lists(risk.reasons, standards.risk.reasons)
    reasons.append(f"行业标准层参考：{standards.summary}")
    return (
        RiskResult(score=final_score, level=_score_to_level(final_score), reasons=_dedupe(reasons)),
        True,
        f"行业标准层将风险上调至 {final_score}/100。",
    )


def _merge_agent_judgment(
    base: AgentJudgment,
    agent_output: dict[str, Any],
    *,
    standards: StandardsAssessment | None,
) -> AgentJudgment:
    final_risk = _coerce_risk_result(agent_output.get("final_risk"), base.final_risk)
    standards_risk = standards.risk if standards else base.standards_risk

    adjustment_reason = _coerce_str(agent_output.get("adjustment_reason"), base.adjustment_reason)
    score_adjusted = _coerce_bool(agent_output.get("score_adjusted"), base.score_adjusted)
    if standards_risk is not None and final_risk.score < standards_risk.score:
        final_risk = RiskResult(
            score=standards_risk.score,
            level=standards_risk.level,
            reasons=_merge_reason_lists(final_risk.reasons, standards_risk.reasons),
        )
        score_adjusted = True
        adjustment_reason = f"{adjustment_reason}；行业标准层将最终风险上调。"

    standards_references = _coerce_str_list(agent_output.get("standards_references"), base.standards_references)
    standards_summary = _coerce_str(agent_output.get("standards_summary"), base.standards_summary)
    standards_consistency = _coerce_str(agent_output.get("standards_consistency"), base.standards_consistency)

    return AgentJudgment(
        has_anomaly=_coerce_bool(agent_output.get("has_anomaly"), base.has_anomaly),
        suspected_attack=_coerce_bool(agent_output.get("suspected_attack"), base.suspected_attack),
        attack_types=_coerce_str_list(agent_output.get("attack_types"), base.attack_types),
        attack_success_assessment=_coerce_str(agent_output.get("attack_success_assessment"), base.attack_success_assessment),
        false_positive_assessment=_coerce_str(agent_output.get("false_positive_assessment"), base.false_positive_assessment),
        evidence_sufficiency=_coerce_str(agent_output.get("evidence_sufficiency"), base.evidence_sufficiency),
        confidence=_coerce_str(agent_output.get("confidence"), base.confidence),
        tool_risk=base.tool_risk,
        final_risk=final_risk,
        score_adjusted=score_adjusted,
        adjustment_reason=adjustment_reason,
        standards_summary=standards_summary,
        standards_references=standards_references,
        standards_consistency=standards_consistency,
        standards_risk=standards_risk,
        analysis_path=_coerce_str_list(agent_output.get("analysis_path"), base.analysis_path),
    )


def _coerce_risk_result(value: Any, fallback: RiskResult) -> RiskResult:
    if isinstance(value, RiskResult):
        return value
    if not isinstance(value, dict):
        return fallback

    score = _coerce_int(value.get("score"), fallback.score)
    level = _coerce_str(value.get("level"), _score_to_level(score))
    reasons = _coerce_str_list(value.get("reasons"), fallback.reasons)
    return RiskResult(score=score, level=level, reasons=reasons)


def _coerce_str(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _coerce_bool(value: Any, fallback: bool) -> bool:
    if value is None:
        return fallback
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "是"}:
            return True
        if normalized in {"false", "0", "no", "n", "否"}:
            return False
    return bool(value)


def _coerce_int(value: Any, fallback: int) -> int:
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _coerce_str_list(value: Any, fallback: list[str] | None = None) -> list[str]:
    if value is None:
        return list(fallback or [])
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else list(fallback or [])
    if isinstance(value, list | tuple):
        items = [str(item).strip() for item in value if str(item).strip()]
        return items or list(fallback or [])
    return list(fallback or [])


def _merge_str_lists(base: list[str], extra: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in [*base, *extra]:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return merged


def _merge_reason_lists(*lists: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for items in lists:
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
    return merged


def _confidence(
    findings: list[Finding],
    success_assessment: str,
    evidence_sufficiency: str,
    adjusted: bool,
) -> str:
    if success_assessment == "疑似攻击成功" and any(finding.kind == "success_after_failures" for finding in findings):
        return "高置信度"
    if "缺口" in evidence_sufficiency or "未提供" in evidence_sufficiency:
        return "低置信度"
    if adjusted:
        return "中置信度"
    if findings:
        return "中置信度"
    return "低置信度"


def _analysis_path(log_type: str, selected_tools: list[str], standards: StandardsAssessment | None) -> list[str]:
    path = [
        "读取用户提供的日志文本或文件路径。",
        "使用 Python 工具解析日志并提取关键字段。",
        f"日志类型判断结果：{log_type}。",
        f"调用 Python 辅助工具：{', '.join(selected_tools)}。",
    ]
    if standards is not None:
        path.append(f"对照行业标准层：{standards.summary}")
        if standards.retrieved_context:
            path.append(f"检索行业标准片段：命中 {len(standards.retrieved_context)} 个上下文。")
    path.append("结合日志证据、Python 风险提示和行业标准层做出最终安全判断。")
    return path


def _is_failed_web_finding(finding: Finding) -> bool:
    status_code = finding.details.get("status_code")
    if status_code is None:
        return False
    return int(status_code) >= 400 or finding.details.get("success") is False


def _score_to_level(score: int) -> str:
    if score <= 30:
        return "低危"
    if score <= 60:
        return "中危"
    if score <= 80:
        return "高危"
    return "严重"


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
