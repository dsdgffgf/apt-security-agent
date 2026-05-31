from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

from .models import AgentJudgment, FailedLoginStats, Finding, RiskResult, StandardsAssessment, SummaryData
from .standards import format_standards_brief, format_standards_lines


ATTACK_LABELS = {
    "bruteforce": "暴力破解尝试",
    "success_after_failures": "多次失败后成功登录",
    "account_enumeration": "账号枚举",
    "high_frequency_ip": "高频访问",
    "abnormal_failure_ip": "失败登录集中",
    "web_scan": "Web 扫描",
    "sql_injection": "SQL 注入",
    "xss": "XSS",
    "directory_traversal": "目录遍历",
    "command_injection": "命令注入",
    "sensitive_file_access": "敏感文件访问",
    "suspicious_external_ip": "可疑外部 IP",
    "api_abnormal_call": "API 异常调用",
    "permission_anomaly": "权限异常",
    "device_offline": "设备离线",
    "frequent_device_state_change": "设备状态频繁变化",
    "off_hours_access": "非工作时段访问",
}


def build_security_report(
    summary: SummaryData,
    findings: Iterable[Finding],
    risk: RiskResult,
    *,
    log_type: str = "unknown",
    source: str | None = None,
    recommendations: list[str] | None = None,
    selected_tools: list[str] | None = None,
    judgment: AgentJudgment | None = None,
    failed_login_stats: FailedLoginStats | None = None,
    tool_findings: dict[str, list[Finding]] | None = None,
    standards: StandardsAssessment | None = None,
    qwen_agent_used: bool = False,
) -> str:
    finding_list = list(findings)
    attack_types = _summarize_attack_types(finding_list)
    final_risk = judgment.final_risk if judgment else risk
    advice = recommendations or _default_recommendations(final_risk)

    lines: list[str] = ["# 日志安全分析报告", ""]
    lines.extend(_brief_analysis_object_section(log_type, source, summary, selected_tools, qwen_agent_used))
    lines.extend(_brief_conclusion_section(risk, final_risk, judgment, attack_types, finding_list))
    lines.extend(_brief_evidence_section(summary, finding_list))
    lines.extend(_brief_standards_section(standards, judgment))
    lines.extend(_brief_recommendation_section(advice))
    return "\n".join(lines).rstrip()


def _brief_analysis_object_section(
    log_type: str,
    source: str | None,
    summary: SummaryData,
    selected_tools: list[str] | None,
    qwen_agent_used: bool,
) -> list[str]:
    return [
        "## 1. 分析对象",
        f"- 数据来源：{source or '日志文本'}",
        f"- 日志类型：{_describe_log_type(log_type)}",
        f"- 分析范围：{_format_time(summary.time_start)} 至 {_format_time(summary.time_end)}",
        f"- 是否使用 Python 工具辅助：{'是' if selected_tools else '否'}",
        f"- 是否由接入 DeepSeek 大模型 API 的智能体完成综合判断：{'是' if qwen_agent_used else '否'}",
        "",
    ]


def _brief_conclusion_section(
    tool_risk: RiskResult,
    final_risk: RiskResult,
    judgment: AgentJudgment | None,
    attack_types: list[str],
    findings: list[Finding],
) -> list[str]:
    has_anomaly = judgment.has_anomaly if judgment is not None else bool(findings)
    suspected_attack = judgment.suspected_attack if judgment is not None else bool(attack_types)
    confidence = judgment.confidence if judgment is not None else "未知"
    attack_success = judgment.attack_success_assessment if judgment is not None else "当前证据不足"
    consistency = judgment.standards_consistency if judgment is not None else "未提供"
    standards_summary = judgment.standards_summary if judgment is not None else "未提供"
    adjusted = judgment.score_adjusted if judgment is not None else False

    return [
        "## 2. 结论摘要",
        f"- Python 风险：{tool_risk.score}/100（{tool_risk.level}）",
        f"- 最终风险：{final_risk.score}/100（{final_risk.level}）",
        f"- 是否异常：{'是' if has_anomaly else '否'}",
        f"- 是否疑似攻击：{'是' if suspected_attack else '否'}",
        f"- 主要攻击类型：{_format_list(attack_types) if attack_types else '暂无明确攻击'}",
        f"- 攻击成功性判断：{attack_success}",
        f"- 置信度：{confidence}",
        f"- 是否参考或调整 Python 风险提示：{'是' if adjusted else '否'}",
        f"- 标准层一致性：{consistency}",
        f"- 标准层摘要：{standards_summary}",
        "",
    ]


def _brief_evidence_section(summary: SummaryData, findings: list[Finding]) -> list[str]:
    lines = ["## 3. 关键证据"]
    if summary.high_risk_accounts:
        lines.append(f"- 高风险账号：{_format_top_items(summary.high_risk_accounts)}")
    if summary.failure_events:
        lines.append(f"- 失败事件数：{summary.failure_events}")

    evidence = _key_evidence_lines(findings)
    if evidence:
        for item in evidence[:3]:
            lines.append(f"- {item}")
    else:
        lines.append("- 当前日志未提取到足够的异常证据。")
    lines.append("")
    return lines


def _brief_standards_section(standards: StandardsAssessment | None, judgment: AgentJudgment | None) -> list[str]:
    lines = ["## 4. 行业标准依据"]
    if standards is None:
        lines.append("- 行业标准摘要：未提供")
    else:
        lines.append(f"- 行业标准摘要：{format_standards_brief(standards)}")
        lines.append(f"- 行业标准风险：{standards.risk.score}/100（{standards.risk.level}）")
        references = ", ".join(
            f"{reference.framework} {reference.code} {reference.title}" for reference in standards.references[:5]
        )
        if references:
            lines.append(f"- 标准引用：{references}")
        else:
            lines.append("- 标准引用：未提供")
    if judgment and judgment.standards_references:
        lines.append(f"- 智能体标准引用：{', '.join(judgment.standards_references[:5])}")
    lines.append("")
    return lines


def _brief_recommendation_section(recommendations: list[str]) -> list[str]:
    lines = ["## 5. 处置建议"]
    lines.extend(f"- {item}" for item in recommendations[:4])
    lines.append("")
    return lines


def _analysis_object_section(
    log_type: str,
    source: str | None,
    summary: SummaryData,
    selected_tools: list[str] | None,
    qwen_agent_used: bool,
) -> list[str]:
    python_tools_used = bool(selected_tools)
    return [
        "## 1. 分析对象",
        f"- 数据来源：{source or '日志文本'}",
        f"- 日志类型：{_describe_log_type(log_type)}",
        f"- 分析范围：{_format_time(summary.time_start)} 至 {_format_time(summary.time_end)}",
        f"- 是否使用 Python 工具辅助：{'是' if python_tools_used else '否'}",
        f"- 是否由接入 DeepSeek 大模型 API 的智能体完成综合判断：{'是' if qwen_agent_used else '否'}",
        "",
    ]


def _analysis_path_section(judgment: AgentJudgment | None, selected_tools: list[str] | None) -> list[str]:
    lines = ["## 2. 智能体分析路径"]
    path = judgment.analysis_path if judgment and judgment.analysis_path else [
        "读取用户提供的日志文本或文件路径。",
        f"调用 Python 辅助工具：{', '.join(selected_tools or ['parse_log', 'summarize_log', 'extract_basic_patterns'])}。",
        "结合基础异常、行业标准层和日志证据进行综合判断。",
    ]
    lines.append("- 分析路径：")
    lines.extend(f"  - {item}" for item in path)
    lines.append("")
    return lines


def _summary_section(summary: SummaryData) -> list[str]:
    lines = [
        "## 3. 日志概况",
        f"- 日志总数：{summary.total_events}",
        f"- 时间范围：{_format_time(summary.time_start)} 至 {_format_time(summary.time_end)}",
        f"- 涉及 IP 数量：{summary.ip_count}",
        f"- 涉及账号数量：{summary.account_count}",
        f"- 成功事件数：{summary.success_events}",
        f"- 失败事件数：{summary.failure_events}",
        f"- 高频 IP：{_format_top_items(summary.top_ips)}",
        f"- 高频账号：{_format_top_items(summary.top_accounts)}",
    ]
    if summary.high_risk_accounts:
        lines.append(f"- 高风险账号：{_format_top_items(summary.high_risk_accounts)}")
    lines.append("")
    return lines


def _tool_results_section(
    summary: SummaryData,
    findings: list[Finding],
    failed_login_stats: FailedLoginStats | None,
    tool_findings: dict[str, list[Finding]],
    risk: RiskResult,
    selected_tools: list[str] | None,
) -> list[str]:
    lines = ["## 4. Python 辅助分析结果"]
    lines.append(f"- Python 工具：{', '.join(selected_tools or ['当前日志中未提供'])}")
    lines.append(
        "- 关键字段："
        f"时间范围 {_format_time(summary.time_start)} 至 {_format_time(summary.time_end)}，"
        f"IP 数量 {summary.ip_count}，账号数量 {summary.account_count}。"
    )
    lines.append(
        "- 统计结果："
        f"日志总数 {summary.total_events}，成功事件 {summary.success_events}，失败事件 {summary.failure_events}。"
    )
    if failed_login_stats is not None:
        lines.append(
            f"- 失败登录辅助统计：共 {len(failed_login_stats.events)} 条，"
            f"高频失败 IP {_format_top_items(failed_login_stats.by_ip)}，"
            f"高频失败账号 {_format_top_items(failed_login_stats.by_account)}。"
        )
    else:
        lines.append("- 失败登录辅助统计：当前日志中未提供。")

    basic_findings = tool_findings.get("extract_basic_patterns") or findings
    if basic_findings:
        lines.append(f"- 基础异常特征：{_format_finding_labels(basic_findings)}。")
    else:
        lines.append("- 基础异常特征：当前日志中未提取到明显异常。")

    lines.append(f"- 风险参考：Python risk_hint 给出 {risk.score}/100，{risk.level}。")

    evidence = _key_evidence_lines(findings)
    if evidence:
        lines.append(f"- 关键证据：{'；'.join(evidence)}")
    else:
        lines.append("- 关键证据：当前日志中未提取到足够的异常证据。")
    lines.append("")
    return lines


def _standards_section(standards: StandardsAssessment | None) -> list[str]:
    lines = ["## 5. 行业标准依据"]
    lines.extend(format_standards_lines(standards))
    lines.append("")
    return lines


def _agent_judgment_section(
    judgment: AgentJudgment | None,
    attack_types: list[str],
    findings: list[Finding],
) -> list[str]:
    lines = ["## 6. 大模型综合判断"]
    if judgment is None:
        lines.extend(
            [
                f"- 是否存在异常：{'是' if findings else '否'}",
                f"- 是否疑似攻击：{'是' if attack_types else '否'}",
                f"- 可能的攻击类型：{_format_list(attack_types) if attack_types else '暂无明确攻击'}",
                "- 攻击成功性判断：当前证据不足以确认。",
                "- 误报可能：需要结合更多上下文复核。",
                "- 证据是否充分：当前仅基于工具结果。",
                "- 置信度：中置信度",
            ]
        )
    else:
        lines.extend(
            [
                f"- 是否存在异常：{'是' if judgment.has_anomaly else '否'}",
                f"- 是否疑似攻击：{'是' if judgment.suspected_attack else '否'}",
                f"- 可能的攻击类型：{_format_list(judgment.attack_types) if judgment.attack_types else '暂无明确攻击'}",
                f"- 攻击成功性判断：{judgment.attack_success_assessment}",
                f"- 误报可能：{judgment.false_positive_assessment}",
                f"- 证据是否充分：{judgment.evidence_sufficiency}",
                f"- 置信度：{judgment.confidence}",
                f"- 标准层一致性：{judgment.standards_consistency}",
                f"- 标准层摘要：{judgment.standards_summary or '当前无可用摘要'}",
            ]
        )
        if judgment.standards_references:
            lines.append(f"- 标准引用：{', '.join(judgment.standards_references)}")
    lines.append("")
    return lines


def _risk_section(
    tool_risk: RiskResult,
    final_risk: RiskResult,
    judgment: AgentJudgment | None,
    standards: StandardsAssessment | None,
) -> list[str]:
    reason = "；".join(final_risk.reasons) if final_risk.reasons else "当前可见证据不足，风险较低。"
    adjusted = judgment.score_adjusted if judgment else False
    adjustment_reason = judgment.adjustment_reason if judgment else "未调整 Python 风险提示。"
    return [
        "## 7. 风险等级",
        f"- Python 风险参考分数：{tool_risk.score}/100",
        f"- Python 风险参考等级：{tool_risk.level}",
        f"- 最终风险分数：{final_risk.score}/100",
        f"- 风险等级：{final_risk.level}",
        f"- 是否参考或调整 Python 风险提示：{'是' if adjusted else '否'}",
        f"- 调整原因：{adjustment_reason}",
        f"- 评分说明：{reason}",
        f"- 行业标准层参考：{standards.summary if standards else '当前未提供'}",
        "",
    ]


def _key_evidence_lines(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for finding in findings[:3]:
        lines.append(f"{_label_for_kind(finding.kind)}：{_format_evidence(finding.evidence)}")
    return lines


def _evidence_section(summary: SummaryData, findings: list[Finding]) -> list[str]:
    lines = ["## 8. 判决依据"]
    evidence_lines: list[str] = []
    if summary.high_risk_accounts:
        evidence_lines.append(f"日志中存在高风险账号：{', '.join(item.key for item in summary.high_risk_accounts)}")
    if summary.failure_events:
        evidence_lines.append(f"失败事件数量为 {summary.failure_events}")
    for finding in findings[:8]:
        evidence_lines.append(f"{_label_for_kind(finding.kind)}：{_format_evidence(finding.evidence)}")
    if not evidence_lines:
        evidence_lines.append("当前日志未提取到足够的异常证据。")
    lines.extend(f"- {line}" for line in evidence_lines)
    lines.append("")
    return lines


def _recommendation_section(recommendations: list[str]) -> list[str]:
    lines = ["## 9. 处置建议"]
    lines.extend(f"- {item}" for item in recommendations)
    lines.append("")
    return lines


def _hardening_section() -> list[str]:
    return [
        "## 10. 后续加固建议",
        "- 启用多因素认证。",
        "- 禁止 root 远程登录，并限制高权限账号的远程访问。",
        "- 优先使用 SSH 密钥登录，减少口令暴露面。",
        "- 配置登录失败锁定策略。",
        "- 部署 Fail2Ban 或等效防护。",
        "- 加强 WAF / 防火墙规则。",
        "- 加强 API 访问控制。",
        "- 定期轮换 API Key。",
        "- 对敏感日志进行脱敏。",
        "- 接入持续日志监控与告警分级流程。",
        "",
    ]


def _conclusion_section(
    risk: RiskResult,
    attack_types: list[str],
    findings: list[Finding],
    judgment: AgentJudgment | None,
) -> list[str]:
    if findings:
        attack_summary = "、".join(attack_types[:3]) if attack_types else "异常行为"
        success = judgment.attack_success_assessment if judgment else "当前证据不足以确认。"
        conclusion = f"当前日志已发现{attack_summary}等异常，风险等级为{risk.level}，攻击成功性判断为{success}。"
        if risk.level in {"高危", "严重"}:
            conclusion += " 建议优先复核相关账号并控制可疑来源。"
        else:
            conclusion += " 建议继续监控并补充验证证据。"
    else:
        conclusion = "当前日志未发现明显异常，建议继续保持监控。"
    return ["## 11. 结论", f"- {conclusion}"]


def _summarize_attack_types(findings: list[Finding]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        label = _label_for_kind(finding.kind)
        if label == "其他异常":
            continue
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def _default_recommendations(risk: RiskResult) -> list[str]:
    if risk.level in {"高危", "严重"}:
        return [
            "立即检查相关账号近期操作记录。",
            "修改相关账号密码并核查高权限账号使用情况。",
            "临时封禁可疑 IP。",
            "检查服务器是否存在异常进程、异常文件或新增账号。",
            "保留日志证据并进行人工复核。",
        ]
    if risk.level == "中危":
        return [
            "核查相关账号近期登录与访问记录。",
            "持续观察可疑 IP 的后续行为。",
            "补充日志与告警证据后再评估是否加固。",
        ]
    return [
        "继续观察相关日志趋势。",
        "若后续出现失败登录增多或异常访问，再提升处置等级。",
    ]


def _format_top_items(items) -> str:
    if not items:
        return "日志中未提供"
    return "、".join(f"{item.key}({item.count})" for item in items[:5])


def _format_evidence(evidence: list[str]) -> str:
    if not evidence:
        return "日志中未提供"
    if len(evidence) == 1:
        return _redact_sensitive(evidence[0])
    return "；".join(_redact_sensitive(item) for item in evidence[:3])


def _format_time(value: datetime | None) -> str:
    if value is None:
        return "日志中未提供"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _label_for_kind(kind: str) -> str:
    return ATTACK_LABELS.get(kind, "其他异常")


def _format_finding_labels(findings: list[Finding]) -> str:
    counter: dict[str, int] = {}
    for finding in findings:
        label = _label_for_kind(finding.kind)
        counter[label] = counter.get(label, 0) + 1
    return "、".join(f"{label}({count})" for label, count in counter.items())


def _format_list(items: list[str]) -> str:
    return "、".join(items)


def _describe_log_type(log_type: str) -> str:
    mapping = {
        "ssh_login": "SSH 登录日志",
        "system_login": "系统登录日志",
        "web_access": "Web 访问日志",
        "firewall": "防火墙日志",
        "waf_alert": "WAF 告警日志",
        "ids_ips_alert": "IDS/IPS 告警日志",
        "cloud_login": "云平台登录日志",
        "api_access": "API 访问日志",
        "iot_event": "IoT 设备事件日志",
        "mixed": "混合日志",
        "unknown": "不明确",
    }
    return mapping.get(log_type, log_type)


def build_pentest_report(result: dict) -> str:
    lines: list[str] = ["# 渗透测试报告", ""]

    lines.append("## 1. 测试目标")
    lines.append(f"- 目标：{result.get('target', '未指定')}")
    lines.append("")

    lines.append("## 2. 端口扫描")
    ports_info = result.get("open_ports_summary", {})
    if isinstance(ports_info, dict):
        lines.append(f"- 开放端口数：{ports_info.get('total', 0)}")
        port_list = ports_info.get("ports", [])
        if port_list:
            lines.append(f"- 端口列表：{', '.join(str(p) for p in port_list)}")
    lines.append("")

    lines.append("## 3. 服务识别")
    services = result.get("services_detected", [])
    if services:
        for svc in services:
            port = svc.get("port", "?")
            name = svc.get("service", "未知")
            version = svc.get("version", "")
            ver_str = f" ({version})" if version else ""
            lines.append(f"- 端口 {port}：{name}{ver_str}")
    else:
        lines.append("- 未识别到服务信息")
    lines.append("")

    web_tech = result.get("web_tech", [])
    discovered_dirs = result.get("discovered_dirs", [])
    if web_tech or discovered_dirs:
        lines.append("## 4. Web 检测")
        if web_tech:
            lines.append(f"- 技术栈：{', '.join(web_tech)}")
        if discovered_dirs:
            lines.append("- 发现的路径：")
            for d in discovered_dirs[:10]:
                path = d.get("path", "?")
                status = d.get("status", "?")
                lines.append(f"  - {path} → HTTP {status}")
        lines.append("")

    headers_info = result.get("security_headers", {})
    if headers_info:
        lines.append("## 5. HTTP 安全头")
        missing = headers_info.get("missing", [])
        present = headers_info.get("present", {})
        risk = headers_info.get("risk_level", "未知")
        lines.append(f"- 风险等级：{risk}")
        if isinstance(present, dict):
            present_str = ', '.join(present.keys()) if present else '无'
        elif isinstance(present, list):
            present_str = ', '.join(str(h) for h in present) if present else '无'
        else:
            present_str = str(present) if present else '无'
        lines.append(f"- 已配置：{present_str}")
        lines.append(f"- 缺失：{', '.join(missing) if missing else '无'}")
        lines.append("")

    form_info = result.get("form_analysis", {})
    if form_info:
        lines.append("## 6. 表单分析")
        lines.append(f"- 表单总数：{form_info.get('total_forms', 0)}")
        lines.append(f"- CSRF 保护：{form_info.get('csrf_protected', 0)} 个")
        lines.append(f"- 风险：{form_info.get('risk', '未知')}")
        lines.append("")

    injection_info = result.get("injection_findings", {})
    if injection_info:
        lines.append("## 7. 参数注入探测")
        reflected = injection_info.get("reflected_params", [])
        lines.append(f"- 反射参数：{', '.join(reflected) if reflected else '无'}")
        lines.append(f"- 风险：{injection_info.get('risk', '未知')}")
        lines.append("")

    vulns = result.get("vulnerabilities", [])
    lines.append("## 8. 漏洞发现")
    if vulns:
        for v in vulns:
            cve = v.get("cve", "未知")
            severity = v.get("severity", "未知")
            service = v.get("service", "")
            desc = v.get("description", "")
            lines.append(f"- [{severity}] {cve} — {service}")
            if desc:
                lines.append(f"  {desc}")
    else:
        lines.append("- 未发现已知漏洞")
    lines.append("")

    risk = result.get("risk_level", "未知")
    lines.append("## 9. 风险等级")
    lines.append(f"- 综合风险：{risk}")
    lines.append("")

    recs = result.get("recommendations", [])
    if recs:
        lines.append("## 10. 修复建议")
        for r in recs:
            lines.append(f"- {r}")
        lines.append("")

    summary = result.get("summary", "")
    if summary:
        lines.append("## 11. 总结")
        lines.append(f"- {summary}")
        lines.append("")

    return "\n".join(lines).rstrip()


def build_attack_report(result: dict) -> str:
    lines: list[str] = ["# 攻击模拟研究报告", ""]

    target_info = result.get("target_info", {})
    lines.append("## 1. 目标信息")
    if target_info:
        lines.append(f"- 目标：{target_info.get('target', '未指定')}")
        ip = target_info.get("ip")
        if ip:
            lines.append(f"- IP 地址：{ip}")
        hostname = target_info.get("hostname")
        if hostname:
            lines.append(f"- 主机名：{hostname}")
    lines.append("")

    payloads = result.get("payloads", [])
    lines.append("## 2. 生成的攻击载荷")
    if payloads:
        for p in payloads:
            ptype = p.get("type", "?").upper()
            payload = p.get("payload", "")
            enc = p.get("encoding", "")
            enc_str = f" [{enc}]" if enc and enc != "plain" else ""
            lines.append(f"- [{ptype}]{enc_str} `{payload}`")
    else:
        lines.append("- 未生成载荷")
    lines.append("")

    bypass = result.get("bypass_variants", {})
    if bypass:
        lines.append("## 3. 编码绕过变体")
        lines.append(f"- 原始载荷：`{bypass.get('original', bypass.get('sqli_original', ''))}`")
        variants = bypass.get("variants", bypass.get("sqli_variants", {}))
        if variants:
            for enc_type, encoded in variants.items():
                preview = str(encoded)[:80]
                lines.append(f"- {enc_type}：`{preview}{'...' if len(str(encoded)) > 80 else ''}`")
        # also show xss and cmd variants if present
        for key in bypass:
            if key.endswith("_original") and key not in ("original", "sqli_original"):
                lines.append(f"- {key.replace('_original', '')} 原始：`{bypass[key]}`")
        lines.append("")

    kill_chain = result.get("kill_chain", [])
    lines.append("## 4. Kill Chain 攻击路径")
    if kill_chain:
        for phase in kill_chain:
            name = phase.get("phase", "?")
            desc = phase.get("description", "")
            tools = phase.get("tools", [])
            tool_str = f" [工具：{', '.join(tools)}]" if tools else ""
            lines.append(f"- **{name}**{tool_str}")
            lines.append(f"  {desc}")
    lines.append("")

    risk_note = result.get("risk_note", "")
    if risk_note:
        lines.append("## 5. 风险声明")
        lines.append(f"- {risk_note}")
        lines.append("")

    summary = result.get("summary", "")
    if summary:
        lines.append("## 6. 总结")
        lines.append(f"- {summary}")
        lines.append("")

    return "\n".join(lines).rstrip()


def build_apt_report(result: dict) -> str:
    """构建 APT 攻击模拟报告"""
    state = result.get("state", {})
    phase_results = result.get("phase_results", [])
    vector = state.get("vector", "firewall_breach")

    vector_labels = {
        "firewall_breach": "A — 互联网边界突破（防火墙→内网扫描→横向移动）",
        "supply_chain": "B — 供应链跳板（利用已控乙方攻击丙方）",
        "phishing": "C — 社工钓鱼（大模型生成中文钓鱼邮件控制设备）",
    }
    lines: list[str] = [
        "# APT 攻击模拟报告",
        "",
        f"## 攻击向量: {vector_labels.get(vector, vector)}",
        "",
    ]

    # 1. 执行摘要
    lines.append("## 1. 执行摘要")
    targets = state.get("targets", [])
    primary = targets[0] if targets else {}
    compromised = [t for t in targets if t.get("compromised")]
    lines.append(f"- 目标：{primary.get('host', '未指定')}")
    lines.append(f"- 沦陷状态：{'是' if compromised else '否'}")
    lines.append(f"- 攻击阶段完成：{sum(1 for p in phase_results if p.get('status') == 'success')}/{len(phase_results)}")
    lines.append(f"- 蓝队感知度：{state.get('blue_team_awareness', 0)}/100")
    lines.append(f"- 模拟开始时间：{state.get('start_time', '未记录')}")
    lines.append("")

    # 2. 攻击路径
    lines.append("## 2. 攻击路径")
    phases_desc = {
        "recon": "情报收集", "social_eng": "社工攻击", "initial_access": "初始突破",
        "persistence": "持久化", "lateral": "横向移动", "cross_target": "跨目标打击",
        "report": "报告生成",
    }
    chain_parts = []
    for pr in phase_results:
        phase = pr.get("phase", "")
        if pr.get("status") == "success" and phase != "report":
            chain_parts.append(phases_desc.get(phase, phase))
    if chain_parts:
        lines.append(f"  internet → {' → '.join(chain_parts)} → 目标沦陷")
    else:
        lines.append("  （未形成完整攻击路径）")
    lines.append("")

    # 3. 阶段详情
    for idx, pr in enumerate(phase_results):
        phase = pr.get("phase", "")
        label = phases_desc.get(phase, phase)
        status = pr.get("status", "pending")
        summary = pr.get("summary", "")
        findings = pr.get("findings", [])

        status_str = {"success": "[OK]", "failed": "[FAIL]", "skipped": "[--]", "pending": "[...]"}.get(status, status)
        lines.append(f"## 3.{idx + 1}. {label}  {status_str}")
        if summary:
            lines.append(f"- 概要：{summary}")
        if findings:
            for f in findings:
                lines.append(f"  - {f}")
        lines.append("")

    # 4. 蓝队对抗分析
    awareness = state.get("blue_team_awareness", 0)
    lines.append("## 4. 蓝队对抗分析")
    lines.append(f"- 最终感知度：{awareness}/100")
    if awareness >= 90:
        lines.append("[!] 攻击链因蓝队感知度过高而终止")
    elif awareness >= 70:
        lines.append("[!] 蓝队已注意到异常活动")
    elif awareness >= 40:
        lines.append("- 蓝队有一定感知，但未影响攻击链执行")
    else:
        lines.append("- 攻击全程未被蓝队有效感知")
    lines.append("")

    # 5. 关键脆弱性
    lines.append("## 5. 关键脆弱性总结")
    all_findings: list[str] = []
    for pr in phase_results:
        all_findings.extend(pr.get("findings", []))
    report_detail = next(
        (pr.get("details", {}).get("report_result", {}) for pr in phase_results
         if pr.get("details", {}).get("report_result")),
        None,
    )
    if report_detail:
        critical = report_detail.get("critical_findings", [])
        if critical:
            for f in critical:
                lines.append(f"[!] {f}")
    elif all_findings:
        for f in all_findings[:8]:
            lines.append(f"- {f}")
    else:
        lines.append("- 无关键发现")
    lines.append("")

    # 6. 加固建议
    lines.append("## 6. 加固建议")
    if report_detail:
        recs = report_detail.get("hardening_recommendations", [])
        if recs:
            for r in recs:
                lines.append(f"- {r}")
    else:
        default_recs = {
            "firewall_breach": [
                "修改防火墙默认口令，关闭管理口公网可达",
                "部署堡垒机替代明文配置文件存储",
                "严格内网段隔离，实施零信任架构",
                "完善日志审计和文件完整性监控",
            ],
            "supply_chain": [
                "取消供应商与客户之间的长期 VPN 直连，改为按需审批临时接入",
                "为每个供应商使用独立 VPN 账号和 ACL 策略",
                "审计所有第三方远程运维通道",
                "定期审查供应商安全资质",
            ],
            "phishing": [
                "部署 AI 反钓鱼邮件网关，重点检测冒充领导的钓鱼邮件",
                "全员安全意识培训 + 钓鱼演练（每季度一次）",
                "启用邮件外链安全检测和沙箱分析",
                "OA/邮箱系统实施 MFA 多因素认证",
            ],
        }
        for r in default_recs.get(vector, default_recs["firewall_breach"]):
            lines.append(f"- {r}")
    lines.append("")

    return "\n".join(lines).rstrip()


def _redact_sensitive(text: str) -> str:
    text = re.sub(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;&|]+", r"\1[REDACTED]", text)
    patterns = (
        ("password=", "password=[REDACTED]"),
        ("passwd=", "passwd=[REDACTED]"),
        ("token=", "token=[REDACTED]"),
        ("api_key=", "api_key=[REDACTED]"),
        ("apikey=", "apikey=[REDACTED]"),
        ("secret=", "secret=[REDACTED]"),
    )
    lowered = text.lower()
    redacted = text
    for marker, replacement in patterns:
        index = lowered.find(marker)
        if index == -1:
            continue
        end = index + len(marker)
        while end < len(redacted) and redacted[end] not in " \t,;&|":
            end += 1
        redacted = redacted[:index] + replacement + redacted[end:]
        lowered = redacted.lower()
    return redacted
