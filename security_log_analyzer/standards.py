from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Finding, RiskResult, StandardReference, StandardsAssessment, SummaryData
from .rag.retriever import retrieve_standards
from .rag.schemas import RagHit


@dataclass(frozen=True, slots=True)
class _StandardRule:
    kind: str
    score: int
    summary_label: str
    evidence_hint: str
    references: tuple[StandardReference, ...]
    query_terms: tuple[str, ...]
    reason: str


def _ref(
    framework: str,
    code: str,
    title: str,
    severity_hint: str,
    *,
    finding_kind: str = "",
    description: str = "",
) -> StandardReference:
    return StandardReference(
        framework=framework,
        code=code,
        title=title,
        severity_hint=severity_hint,
        finding_kind=finding_kind,
        description=description,
    )


def _rule(
    kind: str,
    score: int,
    summary_label: str,
    evidence_hint: str,
    reason: str,
    *,
    query_terms: tuple[str, ...],
    references: tuple[StandardReference, ...],
) -> _StandardRule:
    return _StandardRule(
        kind=kind,
        score=score,
        summary_label=summary_label,
        evidence_hint=evidence_hint,
        reason=reason,
        query_terms=query_terms,
        references=references,
    )


_STANDARD_RULES: dict[str, _StandardRule] = {
    "bruteforce": _rule(
        "bruteforce",
        82,
        "认证失败与暴力破解",
        "连续失败登录、密码猜测、成功后失败",
        "认证失败模式与暴力破解特征明显，符合 OWASP A07 / MITRE T1110。",
        query_terms=(
            "brute force",
            "failed login",
            "password guessing",
            "repeated failed login attempts",
            "authentication failures",
            "success after repeated failures",
            "CWE-307",
            "excessive authentication attempts",
        ),
        references=(
            _ref(
                "OWASP",
                "A07",
                "Identification and Authentication Failures",
                "高风险：认证控制失效",
                finding_kind="bruteforce",
                description="认证失败或口令猜测场景",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1110",
                "Brute Force",
                "高风险：暴力破解与密码猜测",
                finding_kind="bruteforce",
                description="重复失败登录与密码猜测",
            ),
            _ref(
                "CWE",
                "CWE-307",
                "Improper Restriction of Excessive Authentication Attempts",
                "高风险：过多认证尝试",
                finding_kind="bruteforce",
                description="过多认证失败尝试",
            ),
        ),
    ),
    "success_after_failures": _rule(
        "success_after_failures",
        90,
        "多次失败后成功登录",
        "多次失败后出现成功、成功登录、疑似入侵成功",
        "存在多次失败后成功的强证据，符合认证失败后突破的高危情形。",
        query_terms=(
            "success after failures",
            "accepted password",
            "multiple failed attempts",
            "successful login after failures",
            "authentication failures",
            "brute force",
            "valid accounts",
            "CWE-307",
        ),
        references=(
            _ref(
                "OWASP",
                "A07",
                "Identification and Authentication Failures",
                "严重：认证失败后成功",
                finding_kind="success_after_failures",
                description="认证失败后出现成功登录",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1110",
                "Brute Force",
                "严重：暴力破解成功",
                finding_kind="success_after_failures",
                description="多次失败后成功访问",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1078",
                "Valid Accounts",
                "严重：有效账号被滥用",
                finding_kind="success_after_failures",
                description="成功登录后可能使用了有效账号",
            ),
            _ref(
                "CWE",
                "CWE-307",
                "Improper Restriction of Excessive Authentication Attempts",
                "严重：认证尝试限制不足",
                finding_kind="success_after_failures",
                description="多次失败后成功登录",
            ),
        ),
    ),
    "account_enumeration": _rule(
        "account_enumeration",
        72,
        "账号枚举",
        "同一来源尝试多个账号、用户名探测",
        "同一来源对多个账号进行试探，符合账号枚举和口令猜测前置行为。",
        query_terms=(
            "account enumeration",
            "username probing",
            "multiple accounts",
            "account discovery",
            "repeated login attempts across many accounts",
            "CWE-203",
            "observable discrepancy",
        ),
        references=(
            _ref(
                "OWASP",
                "A07",
                "Identification and Authentication Failures",
                "中高风险：账号探测",
                finding_kind="account_enumeration",
                description="账号探测与认证失败",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1087",
                "Account Discovery",
                "中高风险：账号发现",
                finding_kind="account_enumeration",
                description="用户名枚举与账号发现",
            ),
            _ref(
                "CWE",
                "CWE-203",
                "Observable Discrepancy",
                "中高风险：可观察差异",
                finding_kind="account_enumeration",
                description="账号枚举与可观察差异",
            ),
        ),
    ),
    "high_frequency_ip": _rule(
        "high_frequency_ip",
        55,
        "高频访问",
        "高频请求、批量探测、扫描行为",
        "同一来源访问频率偏高，符合批量探测或主动扫描前兆。",
        query_terms=(
            "high frequency ip",
            "active scanning",
            "reconnaissance",
            "many endpoints",
            "abnormal access patterns",
        ),
        references=(
            _ref(
                "MITRE ATT&CK",
                "T1595",
                "Active Scanning",
                "中风险：主动扫描",
                finding_kind="high_frequency_ip",
                description="高频探测与扫描",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：异常连接监测",
                finding_kind="high_frequency_ip",
                description="对异常连接与扫描行为进行监测",
            ),
        ),
    ),
    "abnormal_failure_ip": _rule(
        "abnormal_failure_ip",
        78,
        "失败登录集中",
        "失败登录激增、口令猜测、喷洒式登录",
        "同一 IP 出现多次失败登录，符合口令猜测或暴力破解前兆。",
        query_terms=(
            "failed password burst",
            "authentication failure burst",
            "password spraying",
            "failed login attempts",
            "brute force",
        ),
        references=(
            _ref(
                "OWASP",
                "A07",
                "Identification and Authentication Failures",
                "高风险：认证失败集中",
                finding_kind="abnormal_failure_ip",
                description="失败登录集中与认证失败",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1110",
                "Brute Force",
                "高风险：密码喷洒或暴力破解",
                finding_kind="abnormal_failure_ip",
                description="失败登录激增与密码猜测",
            ),
        ),
    ),
    "web_scan": _rule(
        "web_scan",
        60,
        "Web 扫描",
        "路径探测、目录枚举、主动扫描",
        "同一来源探测多个 Web 路径，符合主动扫描或路径枚举特征。",
        query_terms=(
            "web scanning",
            "active scanning",
            "path enumeration",
            "reconnaissance",
            "directory enumeration",
        ),
        references=(
            _ref(
                "MITRE ATT&CK",
                "T1595",
                "Active Scanning",
                "中风险：主动扫描",
                finding_kind="web_scan",
                description="Web 扫描与路径探测",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：未经授权连接监测",
                finding_kind="web_scan",
                description="异常连接与扫描监测",
            ),
        ),
    ),
    "sql_injection": _rule(
        "sql_injection",
        86,
        "SQL 注入",
        "union select、注入载荷、公共端点探测",
        "请求中出现 SQL 注入特征，属于高危注入攻击。",
        query_terms=(
            "sql injection",
            "union select",
            "public-facing application",
            "exploit payload",
            "parameter tampering",
            "CWE-89",
        ),
        references=(
            _ref(
                "OWASP",
                "A03",
                "Injection",
                "高风险：注入攻击",
                finding_kind="sql_injection",
                description="SQL 注入与注入防护",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1190",
                "Exploit Public-Facing Application",
                "高风险：公共端点利用",
                finding_kind="sql_injection",
                description="对外暴露应用的利用尝试",
            ),
            _ref(
                "CWE",
                "CWE-89",
                "SQL Injection",
                "高风险：SQL 语句注入",
                finding_kind="sql_injection",
                description="SQL 语句被注入特殊输入",
            ),
        ),
    ),
    "xss": _rule(
        "xss",
        78,
        "XSS",
        "<script、事件处理器、跨站脚本",
        "请求中出现 XSS 特征，属于典型注入攻击。",
        query_terms=(
            "cross-site scripting",
            "xss",
            "<script",
            "onerror=",
            "onload=",
            "CWE-79",
        ),
        references=(
            _ref(
                "OWASP",
                "A03",
                "Injection",
                "高风险：XSS 注入",
                finding_kind="xss",
                description="跨站脚本与输出编码问题",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1190",
                "Exploit Public-Facing Application",
                "中高风险：公开应用利用",
                finding_kind="xss",
                description="公开应用利用中的脚本注入",
            ),
            _ref(
                "CWE",
                "CWE-79",
                "Cross-Site Scripting",
                "高风险：跨站脚本",
                finding_kind="xss",
                description="页面生成时的输入净化不足",
            ),
        ),
    ),
    "directory_traversal": _rule(
        "directory_traversal",
        82,
        "目录遍历",
        "../、/etc/passwd、敏感路径访问",
        "请求中出现目录遍历或敏感路径访问，符合访问控制失效特征。",
        query_terms=(
            "directory traversal",
            "../",
            "/etc/passwd",
            "file path normalization",
            "unauthorized file access",
            "CWE-22",
            "CWE-200",
        ),
        references=(
            _ref(
                "OWASP",
                "A01",
                "Broken Access Control",
                "高风险：访问控制失效",
                finding_kind="directory_traversal",
                description="目录遍历与敏感资源访问",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1005",
                "Data from Local System",
                "高风险：本地系统数据读取",
                finding_kind="directory_traversal",
                description="从本地系统读取数据",
            ),
            _ref(
                "CWE",
                "CWE-22",
                "Path Traversal",
                "高风险：路径遍历",
                finding_kind="directory_traversal",
                description="通过未规范化路径访问受限文件",
            ),
            _ref(
                "CWE",
                "CWE-200",
                "Exposure of Sensitive Information to an Unauthorized Actor",
                "高风险：敏感信息暴露",
                finding_kind="directory_traversal",
                description="目录遍历导致敏感信息泄露",
            ),
        ),
    ),
    "command_injection": _rule(
        "command_injection",
        90,
        "命令注入",
        "shell metacharacters、bash -c、powershell、wget/curl",
        "请求中出现命令执行载荷，属于高危命令注入。",
        query_terms=(
            "command injection",
            "shell metacharacters",
            "bash -c",
            "powershell",
            "wget",
            "curl",
            "cmd=",
            "CWE-78",
        ),
        references=(
            _ref(
                "OWASP",
                "A03",
                "Injection",
                "严重：命令注入",
                finding_kind="command_injection",
                description="命令注入与注入防护",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1059",
                "Command and Scripting Interpreter",
                "严重：命令执行",
                finding_kind="command_injection",
                description="命令与脚本解释器滥用",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1190",
                "Exploit Public-Facing Application",
                "严重：公开端点被利用",
                finding_kind="command_injection",
                description="对外暴露应用的利用与注入",
            ),
            _ref(
                "CWE",
                "CWE-78",
                "OS Command Injection",
                "严重：操作系统命令注入",
                finding_kind="command_injection",
                description="命令分隔符和 shell 元字符注入",
            ),
        ),
    ),
    "sensitive_file_access": _rule(
        "sensitive_file_access",
        88,
        "敏感文件访问",
        "/etc/passwd、web.config、.ssh/id_rsa 等敏感路径",
        "请求中出现敏感文件访问，符合本地系统数据读取或越权访问。",
        query_terms=(
            "sensitive file access",
            "/etc/passwd",
            "web.config",
            ".ssh/id_rsa",
            "local system data",
            "shadow",
            "CWE-200",
        ),
        references=(
            _ref(
                "OWASP",
                "A01",
                "Broken Access Control",
                "严重：敏感资源越权",
                finding_kind="sensitive_file_access",
                description="敏感文件和越权访问",
            ),
            _ref(
                "MITRE ATT&CK",
                "T1005",
                "Data from Local System",
                "严重：读取本地敏感数据",
                finding_kind="sensitive_file_access",
                description="本地系统敏感数据读取",
            ),
            _ref(
                "CWE",
                "CWE-200",
                "Exposure of Sensitive Information to an Unauthorized Actor",
                "严重：敏感信息暴露",
                finding_kind="sensitive_file_access",
                description="敏感文件直接暴露给未授权访问者",
            ),
        ),
    ),
    "suspicious_external_ip": _rule(
        "suspicious_external_ip",
        58,
        "可疑外部 IP",
        "外部来源、异常连接、可疑探测",
        "外部 IP 与异常行为同时出现，建议重点跟踪。",
        query_terms=(
            "suspicious external ip",
            "abnormal access patterns",
            "suspicious connections",
            "reconnaissance",
            "active scanning",
        ),
        references=(
            _ref(
                "MITRE ATT&CK",
                "T1595",
                "Active Scanning",
                "中风险：主动扫描",
                finding_kind="suspicious_external_ip",
                description="外部 IP 的探测行为",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：未经授权连接监测",
                finding_kind="suspicious_external_ip",
                description="未经授权连接监测",
            ),
        ),
    ),
    "api_abnormal_call": _rule(
        "api_abnormal_call",
        72,
        "API 异常调用",
        "异常调用、鉴权失败、敏感接口探测",
        "API 调用频率或失败模式异常，符合接口探测或越权尝试。",
        query_terms=(
            "api abnormal call",
            "api authentication",
            "authorization failure",
            "sensitive endpoint probing",
            "broken authentication",
            "broken object level authorization",
            "broken function level authorization",
            "insufficient logging and monitoring",
            "anomalous events",
            "incident response",
            "containment",
            "CWE-306",
            "CWE-285",
        ),
        references=(
            _ref(
                "OWASP API Security",
                "API1",
                "Broken Object Level Authorization",
                "中风险：对象级授权失效",
                finding_kind="api_abnormal_call",
                description="对象级授权控制缺失",
            ),
            _ref(
                "OWASP API Security",
                "API2",
                "Broken Authentication",
                "中风险：API 认证失效",
                finding_kind="api_abnormal_call",
                description="API 身份认证失效",
            ),
            _ref(
                "OWASP API Security",
                "API5",
                "Broken Function Level Authorization",
                "中风险：函数级授权失效",
                finding_kind="api_abnormal_call",
                description="API 功能级授权缺失",
            ),
            _ref(
                "OWASP API Security",
                "API10",
                "Insufficient Logging & Monitoring",
                "中风险：日志与监控不足",
                finding_kind="api_abnormal_call",
                description="API 监控和审计不足",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：异常 API 访问",
                finding_kind="api_abnormal_call",
                description="异常连接和软件监测",
            ),
            _ref(
                "NIST CSF",
                "PR.AC-4",
                "Access Permissions and Authorizations Managed",
                "中风险：访问授权管理",
                finding_kind="api_abnormal_call",
                description="授权与访问权限管理",
            ),
            _ref(
                "NIST CSF",
                "DE.AE-1",
                "Anomalous Events Are Detected",
                "中风险：异常事件检测",
                finding_kind="api_abnormal_call",
                description="异常 API 调用属于可检测异常事件",
            ),
            _ref(
                "NIST CSF",
                "RS.MI-1",
                "Incidents Are Contained",
                "中风险：事件处置与隔离",
                finding_kind="api_abnormal_call",
                description="异常 API 调用需要隔离和处置",
            ),
            _ref(
                "CWE",
                "CWE-306",
                "Missing Authentication for Critical Function",
                "中风险：关键功能缺少认证",
                finding_kind="api_abnormal_call",
                description="关键 API 函数缺少认证",
            ),
            _ref(
                "CWE",
                "CWE-285",
                "Improper Authorization",
                "中风险：授权控制不足",
                finding_kind="api_abnormal_call",
                description="API 授权决策不足",
            ),
        ),
    ),
    "permission_anomaly": _rule(
        "permission_anomaly",
        70,
        "权限异常",
        "未授权、拒绝、权限不足、授权异常",
        "日志中出现权限拒绝或授权异常，属于访问控制风险。",
        query_terms=(
            "permission anomaly",
            "unauthorized",
            "access denied",
            "forbidden",
            "authorization anomalies",
            "broken object level authorization",
            "broken function level authorization",
            "CWE-285",
            "CWE-306",
        ),
        references=(
            _ref(
                "OWASP API Security",
                "API1",
                "Broken Object Level Authorization",
                "中高风险：对象级授权异常",
                finding_kind="permission_anomaly",
                description="对象访问授权不足",
            ),
            _ref(
                "OWASP API Security",
                "API5",
                "Broken Function Level Authorization",
                "中高风险：函数级授权异常",
                finding_kind="permission_anomaly",
                description="功能执行授权不足",
            ),
            _ref(
                "NIST CSF",
                "PR.AC-4",
                "Access Permissions and Authorizations Managed",
                "中高风险：授权异常",
                finding_kind="permission_anomaly",
                description="权限与授权管理",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-1",
                "Monitoring Processes and Procedures",
                "中风险：监测流程与程序",
                finding_kind="permission_anomaly",
                description="监测流程和程序",
            ),
            _ref(
                "NIST CSF",
                "DE.AE-1",
                "Anomalous Events Are Detected",
                "中风险：异常事件检测",
                finding_kind="permission_anomaly",
                description="权限异常属于可检测事件",
            ),
            _ref(
                "CWE",
                "CWE-285",
                "Improper Authorization",
                "中高风险：授权不足",
                finding_kind="permission_anomaly",
                description="授权逻辑不足导致的权限异常",
            ),
            _ref(
                "CWE",
                "CWE-306",
                "Missing Authentication for Critical Function",
                "中高风险：关键功能缺少认证",
                finding_kind="permission_anomaly",
                description="关键功能缺少身份验证",
            ),
        ),
    ),
    "device_offline": _rule(
        "device_offline",
        60,
        "设备离线",
        "设备离线、连接中断、异常状态",
        "设备离线属于异常状态变化，需要结合上下文确认影响范围。",
        query_terms=(
            "device offline",
            "monitoring processes",
            "unusual operational events",
            "alerting",
        ),
        references=(
            _ref(
                "NIST CSF",
                "DE.CM-1",
                "Monitoring Processes and Procedures",
                "中风险：监测流程异常",
                finding_kind="device_offline",
                description="设备状态监测",
            ),
        ),
    ),
    "frequent_device_state_change": _rule(
        "frequent_device_state_change",
        68,
        "设备状态频繁变化",
        "设备状态变化频繁、连接不稳定、异常运行",
        "同一设备短时间内状态变化频繁，符合设备异常运行模式。",
        query_terms=(
            "frequent device state change",
            "monitoring processes",
            "unusual operational events",
            "device behavior",
        ),
        references=(
            _ref(
                "NIST CSF",
                "DE.CM-1",
                "Monitoring Processes and Procedures",
                "中风险：监测与告警",
                finding_kind="frequent_device_state_change",
                description="设备行为监测",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：异常设备连接",
                finding_kind="frequent_device_state_change",
                description="异常设备连接与软件监测",
            ),
        ),
    ),
    "off_hours_access": _rule(
        "off_hours_access",
        62,
        "非工作时间访问",
        "off-hours access、时间窗异常、授权异常",
        "成功访问发生在非工作时间，建议结合业务上下文和授权记录复核。",
        query_terms=(
            "off-hours access",
            "authorization anomalies",
            "access permissions",
            "privilege review",
            "outside working hours",
        ),
        references=(
            _ref(
                "NIST CSF",
                "PR.AC-4",
                "Access Permissions and Authorizations Managed",
                "中风险：非工作时间授权审查",
                finding_kind="off_hours_access",
                description="访问权限与授权管理",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-7",
                "Monitoring for Unauthorized Connections, Devices, and Software",
                "中风险：异常连接监测",
                finding_kind="off_hours_access",
                description="非工作时间访问与异常连接监测",
            ),
            _ref(
                "NIST CSF",
                "DE.CM-1",
                "Monitoring Processes and Procedures",
                "中风险：异常事件监测",
                finding_kind="off_hours_access",
                description="监测流程和程序",
            ),
        ),
    ),
}

_LOGIN_RELATED_KINDS = {
    "bruteforce",
    "success_after_failures",
    "account_enumeration",
    "abnormal_failure_ip",
    "off_hours_access",
}

_LOG_TYPE_CONTEXT_TERMS: dict[str, tuple[str, ...]] = {
    "ssh_login": ("authentication failures", "failed login", "login attempts"),
    "system_login": ("authentication failures", "failed login", "login attempts"),
    "cloud_login": ("authentication failures", "failed login", "login attempts"),
    "web_access": ("public-facing application", "active scanning", "web request"),
    "api_access": ("api authentication", "authorization failure", "sensitive endpoint probing"),
    "iot_event": ("device monitoring", "unusual operational events", "device state change"),
    "firewall": ("monitoring for unauthorized connections", "suspicious connections"),
    "waf_alert": ("injection", "public-facing application", "web attack"),
    "ids_ips_alert": ("monitoring for unauthorized connections", "alerting"),
    "mixed": ("security log analysis", "anomaly detection"),
}


def build_standard_query(
    findings: Iterable[Finding],
    *,
    log_type: str = "unknown",
    summary: SummaryData | None = None,
) -> str:
    finding_list = list(findings)
    lines: list[str] = []

    if log_type:
        lines.append(f"log_type={log_type}")
        for term in _LOG_TYPE_CONTEXT_TERMS.get(log_type, ()):
            lines.append(f"log_type_signal={term}")

    if summary is not None:
        lines.append(
            "summary="
            f"total={summary.total_events}; "
            f"success={summary.success_events}; "
            f"failure={summary.failure_events}; "
            f"ip={summary.ip_count}; "
            f"account={summary.account_count}"
        )
        if summary.high_risk_accounts:
            account_names = ", ".join(item.key for item in summary.high_risk_accounts[:5])
            lines.append(f"high_risk_accounts={account_names}")

    for finding in finding_list:
        rule = _STANDARD_RULES.get(finding.kind)
        lines.append(f"finding_kind={finding.kind}")
        lines.append(f"finding_description={finding.description}")
        if finding.ip:
            lines.append(f"source_ip={finding.ip}")
        if finding.account:
            lines.append(f"account={finding.account}")
        if finding.count:
            lines.append(f"count={finding.count}")
        for fragment in _detail_query_fragments(finding.details):
            lines.append(fragment)
        if rule is None:
            continue
        lines.append(f"rule_focus={rule.summary_label}")
        lines.append(f"rule_hint={rule.evidence_hint}")
        for term in rule.query_terms:
            lines.append(f"signal={term}")
        for reference in rule.references:
            lines.append(f"reference={format_standard_reference(reference)}")

    if not lines:
        lines.append("security log standards retrieval")
    return "\n".join(lines)


def build_standards_assessment(
    findings: Iterable[Finding],
    *,
    log_type: str = "unknown",
    summary: SummaryData | None = None,
    corpus_root: str | Path | None = None,
    retrieval_top_k: int = 5,
) -> StandardsAssessment:
    finding_list = list(findings)
    rules = _collect_rules(finding_list)
    references = _unique_references(reference for rule in rules for reference in rule.references)
    query = build_standard_query(finding_list, log_type=log_type, summary=summary)
    retrieved_context = retrieve_standards(query, corpus_root=corpus_root, top_k=retrieval_top_k)
    risk = _build_risk(finding_list, summary, rules)
    evidence_points = _build_evidence_points(finding_list)
    summary_text = _build_summary_text(references, retrieved_context, finding_list)

    return StandardsAssessment(
        references=references,
        risk=risk,
        summary=summary_text,
        evidence_points=evidence_points,
        retrieval_query=query,
        retrieved_context=retrieved_context,
    )


def format_standard_reference(reference: StandardReference) -> str:
    return f"{reference.framework} {reference.code} {reference.title}".strip()


def format_standards_brief(standards: StandardsAssessment | None) -> str:
    if standards is None:
        return "未记录行业标准层"

    frameworks = _unique_frameworks_from_references(standards.references)
    if not frameworks and standards.retrieved_context:
        frameworks = _unique_frameworks_from_hits(standards.retrieved_context)

    framework_text = " / ".join(frameworks) if frameworks else "行业标准"
    hit_text = f"检索到 {len(standards.retrieved_context)} 个标准片段" if standards.retrieved_context else "未命中本地标准片段"
    return f"{framework_text}：{standards.summary}；{hit_text}"


def format_standards_lines(standards: StandardsAssessment | None) -> list[str]:
    if standards is None:
        return ["- 行业标准层：未生成"]

    lines: list[str] = [
        f"- 行业标准摘要：{standards.summary}",
        f"- 行业标准风险：{standards.risk.score}/100（{standards.risk.level}）",
    ]

    if standards.retrieval_query:
        lines.append(f"- 检索查询：{_excerpt(_normalize_whitespace(standards.retrieval_query), 220)}")

    if standards.evidence_points:
        lines.append(f"- 证据锚点：{_join_items(standards.evidence_points)}")

    if standards.references:
        lines.append("- 标准引用：")
        for reference in standards.references:
            lines.append(f"  - {format_standard_reference(reference)}（{reference.severity_hint}）")

    if standards.retrieved_context:
        lines.append(f"- 检索结果：命中 {len(standards.retrieved_context)} 个标准片段")
        for hit in standards.retrieved_context:
            lines.append(f"  - {_format_hit_summary(hit)}")
            lines.append(f"    {_format_hit_excerpt(hit)}")
    else:
        lines.append("- 检索结果：未命中本地标准片段")

    return lines


def _collect_rules(findings: list[Finding]) -> list[_StandardRule]:
    ordered: list[_StandardRule] = []
    seen: set[str] = set()
    for finding in findings:
        rule = _STANDARD_RULES.get(finding.kind)
        if rule is None or rule.kind in seen:
            continue
        seen.add(rule.kind)
        ordered.append(rule)
    return ordered


def _build_risk(findings: list[Finding], summary: SummaryData | None, rules: list[_StandardRule]) -> RiskResult:
    score = 0
    reasons: list[str] = []

    for finding in findings:
        rule = _STANDARD_RULES.get(finding.kind)
        if rule is None:
            continue
        score = max(score, rule.score)
        reasons.append(_reason_for_finding(finding, rule))

        if finding.kind == "success_after_failures" and finding.details.get("high_risk_account"):
            score = max(score, 95)
            reasons.append("高权限账号在多次失败后成功登录，风险提升到严重级别。")

        if finding.kind in {"sql_injection", "command_injection", "sensitive_file_access"} and finding.details.get("success") is True:
            score = max(score, 95)
            reasons.append("攻击请求已出现成功证据，风险需要上调。")

    if summary is not None and summary.high_risk_accounts and any(finding.kind in _LOGIN_RELATED_KINDS for finding in findings):
        account_names = ", ".join(item.key for item in summary.high_risk_accounts[:3])
        reasons.append(f"日志中出现高风险账号：{account_names}")
        score = max(score, 85)

    if len({finding.kind for finding in findings}) >= 3:
        reasons.append("异常类型较多，呈现组合攻击特征。")
        score = max(score, min(100, score + 5))

    score = max(0, min(100, score))
    return RiskResult(score=score, level=_score_to_level(score), reasons=_dedupe(reasons))


def _build_summary_text(
    references: list[StandardReference],
    retrieved_context: list[RagHit],
    findings: list[Finding],
) -> str:
    frameworks = _unique_frameworks_from_references(references)
    if not frameworks and retrieved_context:
        frameworks = _unique_frameworks_from_hits(retrieved_context)
    if not frameworks:
        frameworks = ["行业标准"]

    finding_text = f"{len(findings)} 个异常模式" if findings else "当前未识别出明确异常"
    hit_text = f"检索到 {len(retrieved_context)} 个相关片段" if retrieved_context else "未命中本地标准片段"
    return f"{' / '.join(frameworks)} 相关标准已对照；{finding_text}；{hit_text}"


def _build_evidence_points(findings: list[Finding]) -> list[str]:
    points: list[str] = []
    for finding in findings:
        parts = [finding.kind, finding.description]
        if finding.ip:
            parts.append(f"IP {finding.ip}")
        if finding.account:
            parts.append(f"账号 {finding.account}")
        text = " - ".join(part for part in parts if part)
        if text and text not in points:
            points.append(text)
        if len(points) >= 5:
            break
    return points


def _reason_for_finding(finding: Finding, rule: _StandardRule) -> str:
    labels = [format_standard_reference(reference) for reference in rule.references[:2]]
    label_text = " / ".join(labels) if labels else rule.summary_label
    return f"{finding.description}，对照 {label_text}。"


def _detail_query_fragments(details: dict[str, object]) -> list[str]:
    if not details:
        return []

    fragments: list[str] = []
    interesting_keys = (
        "path",
        "decoded_path",
        "paths",
        "accounts",
        "device_id",
        "device",
        "states",
        "status_code",
        "status_codes",
        "success",
        "event",
        "status",
    )
    for key in interesting_keys:
        if key not in details:
            continue
        value = details[key]
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple)):
            text = ", ".join(str(item).strip() for item in value if str(item).strip())
        else:
            text = str(value).strip()
        if text:
            fragments.append(f"detail_{key}={text}")
    return fragments


def _format_hit_summary(hit: RagHit) -> str:
    framework = _display_framework(hit.chunk.framework)
    terms = _join_items(hit.matched_terms) if hit.matched_terms else "无"
    return f"[{hit.score:.2f}] {framework} / {hit.chunk.section}（命中词：{terms}）"


def _format_hit_excerpt(hit: RagHit) -> str:
    return _excerpt(_normalize_whitespace(hit.chunk.chunk_text), 220)


def _display_framework(value: str) -> str:
    lowered = value.lower()
    mapping = {
        "owasp": "OWASP",
        "mitre": "MITRE ATT&CK",
        "nist": "NIST CSF",
    }
    return mapping.get(lowered, value.upper())


def _unique_references(references: Iterable[StandardReference]) -> list[StandardReference]:
    output: list[StandardReference] = []
    seen: set[tuple[str, str, str]] = set()
    for reference in references:
        key = (reference.framework, reference.code, reference.title)
        if key in seen:
            continue
        seen.add(key)
        output.append(reference)
    return output


def _unique_frameworks_from_references(references: list[StandardReference]) -> list[str]:
    frameworks: list[str] = []
    seen: set[str] = set()
    for reference in references:
        display = reference.framework
        if display in seen:
            continue
        seen.add(display)
        frameworks.append(display)
    return frameworks


def _unique_frameworks_from_hits(hits: list[RagHit]) -> list[str]:
    frameworks: list[str] = []
    seen: set[str] = set()
    for hit in hits:
        display = _display_framework(hit.chunk.framework)
        if display in seen:
            continue
        seen.add(display)
        frameworks.append(display)
    return frameworks


def _normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def _excerpt(text: str, limit: int = 180) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: max(limit - 1, 1)].rstrip()}…"


def _join_items(items: list[str]) -> str:
    values = [str(item).strip() for item in items if str(item).strip()]
    if not values:
        return "无"
    return "；".join(values)


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


__all__ = [
    "build_standard_query",
    "build_standards_assessment",
    "format_standard_reference",
    "format_standards_brief",
    "format_standards_lines",
]
