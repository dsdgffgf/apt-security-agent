from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Iterable
from urllib.parse import unquote

from .models import Finding, LogRecord, RiskResult, SummaryData


LOGIN_LOG_TYPES = {"ssh_login", "system_login", "cloud_login"}
HIGH_RISK_ACCOUNTS = {"root", "admin", "administrator", "sa", "oracle", "postgres", "mysql"}


def detect_bruteforce(
    records: Iterable[LogRecord],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[Finding]:
    failed_records = [
        record
        for record in records
        if record.succeeded is False and record.log_type in LOGIN_LOG_TYPES and record.ip
    ]
    grouped: dict[str, list[LogRecord]] = defaultdict(list)
    for record in failed_records:
        grouped[record.ip].append(record)

    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)

    for ip, items in grouped.items():
        ordered = sorted(items, key=_record_sort_key)
        best_window = _best_time_window(ordered, window) if any(record.timestamp for record in ordered) else ordered
        if len(best_window) < threshold:
            continue
        accounts = sorted(
            {
                account
                for account in (record.account or record.username for record in best_window)
                if account
            }
        )
        findings.append(
            Finding(
                kind="bruteforce",
                description="同一 IP 在短时间内连续失败登录，疑似暴力破解尝试",
                ip=ip,
                count=len(best_window),
                start_time=best_window[0].timestamp,
                end_time=best_window[-1].timestamp,
                evidence=[record.raw for record in best_window[:5]],
                details={
                    "accounts": accounts,
                    "window_minutes": window_minutes,
                },
            )
        )

    return findings


def detect_success_after_failures(
    records: Iterable[LogRecord],
    threshold: int = 3,
) -> list[Finding]:
    grouped: dict[tuple[str, str], list[LogRecord]] = defaultdict(list)
    ordered_records = list(records)
    for record in ordered_records:
        if record.succeeded is None:
            continue
        if not record.ip and not (record.account or record.username):
            continue
        key = (record.ip or "", record.account or record.username or "")
        grouped[key].append(record)

    findings: list[Finding] = []
    for (ip, account), items in grouped.items():
        ordered = sorted(items, key=_record_sort_key)
        failures: list[LogRecord] = []
        for record in ordered:
            if record.succeeded is False:
                failures.append(record)
                continue
            if record.succeeded is True:
                if len(failures) >= threshold:
                    final_account = account or record.account or record.username or ""
                    is_high_risk = final_account.lower() in HIGH_RISK_ACCOUNTS
                    findings.append(
                        Finding(
                            kind="success_after_failures",
                            description="多次失败后出现成功登录，疑似暴力破解成功",
                            ip=ip or None,
                            account=final_account or None,
                            count=len(failures),
                            start_time=failures[0].timestamp,
                            end_time=record.timestamp,
                            evidence=[*(item.raw for item in failures[:5]), record.raw],
                            details={
                                "prior_failures": len(failures),
                                "success_time": _format_datetime(record.timestamp),
                                "high_risk_account": is_high_risk,
                            },
                        )
                    )
                failures = []

    return findings


def detect_web_attack(records: Iterable[LogRecord]) -> list[Finding]:
    record_list = list(records)
    findings: list[Finding] = []
    suspicious_paths_by_ip: dict[str, set[str]] = defaultdict(set)
    suspicious_counts_by_ip: Counter[str] = Counter()

    for record in record_list:
        if not record.request_path and record.log_type != "web_access":
            continue

        raw_path = record.request_path or record.raw
        decoded_path = unquote(raw_path).lower()
        ip = record.ip
        matched_kinds: list[tuple[str, str]] = []

        if _looks_like_sql_injection(decoded_path):
            matched_kinds.append(("sql_injection", "请求路径包含 SQL 注入特征"))
        if _looks_like_xss(decoded_path):
            matched_kinds.append(("xss", "请求路径包含 XSS 特征"))
        if _looks_like_directory_traversal(decoded_path):
            matched_kinds.append(("directory_traversal", "请求路径包含目录遍历特征"))
        if _looks_like_command_injection(decoded_path):
            matched_kinds.append(("command_injection", "请求路径包含命令注入特征"))
        if _looks_like_sensitive_file_access(decoded_path):
            matched_kinds.append(("sensitive_file_access", "请求路径涉及敏感文件访问"))

        for kind, description in matched_kinds:
            findings.append(
                Finding(
                    kind=kind,
                    description=description,
                    ip=ip,
                    account=record.account or record.username,
                    count=1,
                    start_time=record.timestamp,
                    end_time=record.timestamp,
                    evidence=[record.raw],
                    details={
                        "path": record.request_path,
                        "decoded_path": decoded_path,
                        "status_code": record.status_code,
                        "success": record.succeeded is True,
                    },
                )
            )
            if ip:
                suspicious_paths_by_ip[ip].add(decoded_path)
                suspicious_counts_by_ip[ip] += 1

    for ip, paths in suspicious_paths_by_ip.items():
        if len(paths) >= 3 or suspicious_counts_by_ip[ip] >= 3:
            findings.append(
                Finding(
                    kind="web_scan",
                    description="同一 IP 多次探测不同 Web 路径，疑似扫描行为",
                    ip=ip,
                    count=suspicious_counts_by_ip[ip],
                    evidence=[record.raw for record in record_list if record.ip == ip][:5],
                    details={"paths": sorted(paths)},
                )
            )

    return findings


def detect_abnormal_ip(records: Iterable[LogRecord]) -> list[Finding]:
    record_list = list(records)
    ip_counter = Counter(record.ip for record in record_list if record.ip)
    login_failure_counter = Counter(
        record.ip
        for record in record_list
        if record.ip and record.succeeded is False and record.log_type in LOGIN_LOG_TYPES
    )
    account_sets: dict[str, set[str]] = defaultdict(set)
    path_sets: dict[str, set[str]] = defaultdict(set)
    suspicious_public_ips: set[str] = set()

    for record in record_list:
        if not record.ip:
            continue
        if record.log_type in LOGIN_LOG_TYPES and (record.account or record.username):
            account_sets[record.ip].add(record.account or record.username or "")
        if record.request_path:
            decoded_path = unquote(record.request_path).lower()
            path_sets[record.ip].add(decoded_path)
            if (
                _looks_like_web_probe(decoded_path)
                or _looks_like_sql_injection(decoded_path)
                or _looks_like_xss(decoded_path)
                or _looks_like_directory_traversal(decoded_path)
                or _looks_like_command_injection(decoded_path)
                or _looks_like_sensitive_file_access(decoded_path)
            ):
                suspicious_public_ips.add(record.ip)
        if _is_public_ip(record.ip) and (
            (record.succeeded is False and record.log_type in LOGIN_LOG_TYPES) or record.alert_type
        ):
            suspicious_public_ips.add(record.ip)

    findings: list[Finding] = []

    for ip, count in ip_counter.items():
        if count >= 3:
            findings.append(
                Finding(
                    kind="high_frequency_ip",
                    description="同一 IP 访问频率偏高，可能存在批量探测或扫描",
                    ip=ip,
                    count=count,
                    evidence=[record.raw for record in record_list if record.ip == ip][:5],
                    details={"threshold": 3},
                )
            )

    for ip, count in login_failure_counter.items():
        if count >= 3:
            findings.append(
                Finding(
                    kind="abnormal_failure_ip",
                    description="同一 IP 出现多次失败登录，疑似口令猜测或暴力破解",
                    ip=ip,
                    count=count,
                    evidence=[record.raw for record in record_list if record.ip == ip and record.succeeded is False][:5],
                    details={"threshold": 3},
                )
            )

    for ip, accounts in account_sets.items():
        if len(accounts) >= 3:
            findings.append(
                Finding(
                    kind="account_enumeration",
                    description="同一 IP 尝试多个账号，疑似账号枚举或口令猜测",
                    ip=ip,
                    count=len(accounts),
                    evidence=[
                        record.raw
                        for record in record_list
                        if record.ip == ip and (record.account or record.username)
                    ][:5],
                    details={"accounts": sorted(account for account in accounts if account)},
                )
            )

    for ip, paths in path_sets.items():
        if len(paths) >= 3:
            findings.append(
                Finding(
                    kind="web_scan",
                    description="同一 IP 访问多个不同 Web 路径，疑似扫描",
                    ip=ip,
                    count=len(paths),
                    evidence=[record.raw for record in record_list if record.ip == ip][:5],
                    details={"paths": sorted(paths)},
                )
            )

    for ip in suspicious_public_ips:
        if not _is_public_ip(ip):
            continue
        if ip not in login_failure_counter and not any(
            finding.ip == ip
            and finding.kind in {"high_frequency_ip", "abnormal_failure_ip", "account_enumeration", "web_scan"}
            for finding in findings
        ):
            continue
        findings.append(
            Finding(
                kind="suspicious_external_ip",
                description="该 IP 为外部地址且伴随异常行为，建议重点关注",
                ip=ip,
                count=ip_counter[ip],
                evidence=[record.raw for record in record_list if record.ip == ip][:5],
                details={"public": True},
            )
        )

    return findings


def detect_security_anomaly(records: Iterable[LogRecord]) -> list[Finding]:
    record_list = list(records)
    findings: list[Finding] = []
    findings.extend(detect_bruteforce(record_list))
    findings.extend(detect_success_after_failures(record_list))
    findings.extend(detect_web_attack(record_list))
    findings.extend(detect_abnormal_ip(record_list))
    findings.extend(_detect_api_anomalies(record_list))
    findings.extend(_detect_device_anomalies(record_list))
    findings.extend(_detect_off_hours_access(record_list))
    return _dedupe_findings(findings)


def risk_score(findings: Iterable[Finding], summary: SummaryData | None = None) -> RiskResult:
    finding_list = list(findings)
    score = 0
    reasons: list[str] = []

    for finding in finding_list:
        score += _score_for_finding(finding)
        reasons.append(_reason_for_finding(finding))

    if summary is not None:
        if summary.high_risk_accounts:
            score += 10
            names = ", ".join(item.key for item in summary.high_risk_accounts[:3])
            reasons.append(f"日志中出现高风险账号：{names}")
        if summary.failure_events >= 5:
            score += 5
            reasons.append(f"失败事件数量较多：{summary.failure_events}")

    if any(
        finding.kind == "success_after_failures"
        and finding.account
        and finding.account.lower() in HIGH_RISK_ACCOUNTS
        for finding in finding_list
    ):
        score += 15
        reasons.append("高权限账号存在多次失败后成功登录迹象")

    if len({finding.kind for finding in finding_list}) >= 3:
        score += 10
        reasons.append("异常类型较多，呈现组合攻击特征")

    score = max(0, min(100, score))
    return RiskResult(score=score, level=_score_to_level(score), reasons=_dedupe(reasons))


def _score_for_finding(finding: Finding) -> int:
    weights = {
        "success_after_failures": 40,
        "bruteforce": 18,
        "sql_injection": 22,
        "xss": 18,
        "directory_traversal": 18,
        "command_injection": 24,
        "sensitive_file_access": 25,
        "web_scan": 15,
        "high_frequency_ip": 8,
        "abnormal_failure_ip": 15,
        "account_enumeration": 12,
        "suspicious_external_ip": 8,
        "api_abnormal_call": 18,
        "permission_anomaly": 18,
        "device_offline": 12,
        "frequent_device_state_change": 16,
        "off_hours_access": 12,
    }
    score = weights.get(finding.kind, 5)
    if finding.kind == "success_after_failures" and finding.details.get("high_risk_account"):
        score += 10
    if finding.kind == "sensitive_file_access" and finding.details.get("success") is True:
        score += 10
    if finding.kind in {"sql_injection", "xss", "directory_traversal", "command_injection"} and finding.details.get("success") is True:
        score += 5
    if finding.kind == "bruteforce":
        score += min(max(finding.count - 1, 0), 5)
    if finding.kind == "web_scan":
        score += min(max(finding.count - 2, 0), 5)
    return score


def _detect_api_anomalies(records: list[LogRecord]) -> list[Finding]:
    api_records = [
        record for record in records if record.log_type == "api_access" or _is_api_record(record)
    ]
    by_ip: dict[str, list[LogRecord]] = defaultdict(list)
    permission_records: list[LogRecord] = []

    for record in api_records:
        if record.ip:
            by_ip[record.ip].append(record)
        if _is_permission_denied(record):
            permission_records.append(record)

    findings: list[Finding] = []
    for ip, items in by_ip.items():
        failed_or_sensitive = [
            record
            for record in items
            if (record.status_code is not None and record.status_code >= 400)
            or _looks_like_sensitive_api(record)
        ]
        if len(items) >= 3 and failed_or_sensitive:
            findings.append(
                Finding(
                    kind="api_abnormal_call",
                    description="同一 IP 多次调用 API 且伴随失败或敏感接口访问，疑似 API 异常调用",
                    ip=ip,
                    count=len(items),
                    start_time=items[0].timestamp,
                    end_time=items[-1].timestamp,
                    evidence=[record.raw for record in items[:5]],
                    details={"paths": sorted({record.request_path or "" for record in items if record.request_path})},
                )
            )

    if permission_records:
        grouped_by_ip: dict[str, list[LogRecord]] = defaultdict(list)
        for record in permission_records:
            grouped_by_ip[record.ip or "未知 IP"].append(record)
        for ip, items in grouped_by_ip.items():
            findings.append(
                Finding(
                    kind="permission_anomaly",
                    description="日志中出现未授权、拒绝或权限不足响应，疑似权限异常",
                    ip=None if ip == "未知 IP" else ip,
                    count=len(items),
                    start_time=items[0].timestamp,
                    end_time=items[-1].timestamp,
                    evidence=[record.raw for record in items[:5]],
                    details={"status_codes": sorted({record.status_code for record in items if record.status_code})},
                )
            )

    return findings


def _detect_device_anomalies(records: list[LogRecord]) -> list[Finding]:
    device_records = [
        record
        for record in records
        if record.log_type == "iot_event"
        or any(key in record.fields for key in ("device_id", "device", "event", "status"))
    ]
    findings: list[Finding] = []
    by_device: dict[str, list[LogRecord]] = defaultdict(list)

    for record in device_records:
        device = record.fields.get("device_id") or record.fields.get("device") or record.device_name
        if not device:
            continue
        by_device[device].append(record)
        event_text = " ".join(
            filter(
                None,
                [
                    record.fields.get("event"),
                    record.fields.get("status"),
                    record.event_description,
                ],
            )
        ).lower()
        if "offline" in event_text or "离线" in event_text:
            findings.append(
                Finding(
                    kind="device_offline",
                    description="设备出现离线事件，可能影响设备可用性或指示异常状态",
                    ip=record.ip,
                    account=record.account or record.username,
                    count=1,
                    start_time=record.timestamp,
                    end_time=record.timestamp,
                    evidence=[record.raw],
                    details={"device_id": device},
                )
            )

    for device, items in by_device.items():
        states = {
            (record.fields.get("event") or record.fields.get("status") or "").lower()
            for record in items
            if record.fields.get("event") or record.fields.get("status")
        }
        if len(items) >= 3 and len(states) >= 2:
            ordered = sorted(items, key=_record_sort_key)
            findings.append(
                Finding(
                    kind="frequent_device_state_change",
                    description="同一设备短时间内多次状态变化，疑似设备运行异常或连接不稳定",
                    count=len(items),
                    start_time=ordered[0].timestamp,
                    end_time=ordered[-1].timestamp,
                    evidence=[record.raw for record in ordered[:5]],
                    details={"device_id": device, "states": sorted(states)},
                )
            )

    return findings


def _detect_off_hours_access(records: list[LogRecord]) -> list[Finding]:
    findings: list[Finding] = []
    for record in records:
        if record.timestamp is None or record.succeeded is not True:
            continue
        if record.timestamp.hour < 6 or record.timestamp.hour >= 22:
            findings.append(
                Finding(
                    kind="off_hours_access",
                    description="成功访问或登录发生在非工作时间，建议结合业务上下文复核",
                    ip=record.ip,
                    account=record.account or record.username,
                    count=1,
                    start_time=record.timestamp,
                    end_time=record.timestamp,
                    evidence=[record.raw],
                )
            )
    return findings


def _is_api_record(record: LogRecord) -> bool:
    return bool(record.request_path and record.request_path.lower().startswith("/api"))


def _is_permission_denied(record: LogRecord) -> bool:
    lowered = record.raw.lower()
    if record.status_code in {401, 403}:
        return True
    return any(marker in lowered for marker in ("permission denied", "unauthorized", "forbidden", "access denied"))


def _looks_like_sensitive_api(record: LogRecord) -> bool:
    path = (record.request_path or record.raw).lower()
    return any(marker in path for marker in ("/admin", "/token", "/secret", "/device/control", "/apikey", "/api/key"))


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None, str]] = set()
    output: list[Finding] = []
    for finding in findings:
        first_evidence = finding.evidence[0] if finding.evidence else ""
        key = (finding.kind, finding.ip, finding.account, first_evidence)
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
    return output


def _reason_for_finding(finding: Finding) -> str:
    if finding.kind == "success_after_failures":
        account = finding.account or "未知账号"
        return f"{finding.ip or '未知 IP'} 在多次失败后成功登录 {account}"
    if finding.kind == "bruteforce":
        return f"{finding.ip or '未知 IP'} 在短时间内出现 {finding.count} 次失败登录"
    if finding.kind == "sql_injection":
        return f"{finding.ip or '未知 IP'} 的请求中出现 SQL 注入特征"
    if finding.kind == "xss":
        return f"{finding.ip or '未知 IP'} 的请求中出现 XSS 特征"
    if finding.kind == "directory_traversal":
        return f"{finding.ip or '未知 IP'} 的请求中出现目录遍历特征"
    if finding.kind == "command_injection":
        return f"{finding.ip or '未知 IP'} 的请求中出现命令注入特征"
    if finding.kind == "sensitive_file_access":
        return f"{finding.ip or '未知 IP'} 访问了敏感文件路径"
    if finding.kind == "web_scan":
        return f"{finding.ip or '未知 IP'} 访问了多个不同 Web 路径"
    if finding.kind == "high_frequency_ip":
        return f"{finding.ip or '未知 IP'} 访问频率偏高"
    if finding.kind == "abnormal_failure_ip":
        return f"{finding.ip or '未知 IP'} 出现多次失败登录"
    if finding.kind == "account_enumeration":
        return f"{finding.ip or '未知 IP'} 尝试了多个账号"
    if finding.kind == "suspicious_external_ip":
        return f"{finding.ip or '未知 IP'} 为外部地址且伴随异常行为"
    return finding.description


def _record_sort_key(record: LogRecord) -> tuple[int, datetime]:
    timestamp = record.timestamp or datetime.min
    return (record.line_no or 0, timestamp)


def _best_time_window(records: list[LogRecord], window: timedelta) -> list[LogRecord]:
    if not records:
        return []
    timestamps = [record.timestamp for record in records]
    if any(timestamp is None for timestamp in timestamps):
        return records

    best_start = 0
    best_end = 0
    start = 0
    for end, record in enumerate(records):
        while start <= end and records[start].timestamp is not None and record.timestamp is not None and record.timestamp - records[start].timestamp > window:
            start += 1
        if end - start > best_end - best_start:
            best_start = start
            best_end = end
    return records[best_start : best_end + 1]


def _looks_like_sql_injection(path: str) -> bool:
    patterns = (
        "union select",
        " or 1=1",
        " and 1=1",
        "sleep(",
        "benchmark(",
        "' or '1'='1",
        "\" or \"1\"=\"1",
    )
    return any(pattern in path for pattern in patterns)


def _looks_like_xss(path: str) -> bool:
    patterns = ("<script", "javascript:", "onerror=", "onload=", "%3cscript")
    return any(pattern in path for pattern in patterns)


def _looks_like_directory_traversal(path: str) -> bool:
    patterns = ("../", "..\\", "/etc/passwd", "win.ini", "web.config", ".ssh/id_rsa", "/proc/self/environ")
    return any(pattern in path for pattern in patterns)


def _looks_like_command_injection(path: str) -> bool:
    patterns = ("cmd=", "exec", "powershell", "bash -c", ";", "&&", "|", "`", "wget ", "curl ", "nc ")
    return any(pattern in path for pattern in patterns)


def _looks_like_sensitive_file_access(path: str) -> bool:
    patterns = ("/etc/passwd", "win.ini", "web.config", ".env", ".ssh/id_rsa", "shadow", "/proc/self/environ")
    return any(pattern in path for pattern in patterns)


def _looks_like_web_probe(path: str) -> bool:
    probe_tokens = (
        "/admin",
        "/login",
        "/wp-admin",
        "/phpmyadmin",
        "/.git",
        "/config",
        "/backup",
        "/test",
        "/shell",
        "/etc/passwd",
        "../",
    )
    return any(token in path for token in probe_tokens)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ") if value else None


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
