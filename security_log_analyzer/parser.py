from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import LogRecord, ParseResult


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_METHOD_RE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(.+?)\s+HTTP/\d(?:\.\d)?\b"
)
_STATUS_CODE_RE = re.compile(r'"\s*(\d{3})\s+(\d+|-)')
_KEY_VALUE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_-]*)=([^\s,;|]+)")
_USERNAME_PATTERNS = (
    re.compile(r"Failed password for invalid user (\S+) from", re.IGNORECASE),
    re.compile(r"Failed password for (\S+) from", re.IGNORECASE),
    re.compile(r"Accepted password for (\S+) from", re.IGNORECASE),
    re.compile(r"user(?:name)?[=:]\s*([^\s,;|]+)", re.IGNORECASE),
    re.compile(r"account[=:]\s*([^\s,;|]+)", re.IGNORECASE),
    re.compile(r"login\s*(?:user)?[=:]\s*([^\s,;|]+)", re.IGNORECASE),
)
_TIMESTAMP_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (
        re.compile(
            r"\b(?P<value>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\b"
        ),
        ("%Y-%m-%d %H:%M:%S",),
    ),
    (
        re.compile(
            r"\b(?P<value>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\b"
        ),
        ("%Y/%m/%d %H:%M:%S",),
    ),
    (
        re.compile(
            r"\b(?P<value>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?\b"
        ),
        ("%Y-%m-%dT%H:%M:%S",),
    ),
    (
        re.compile(
            r"\b(?P<value>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})\b"
        ),
        ("%b %d %H:%M:%S",),
    ),
    (
        re.compile(
            r"\b(?P<value>\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})\b"
        ),
        ("%d/%b/%Y:%H:%M:%S",),
    ),
)


def parse_log(source: str | Path) -> ParseResult:
    text, source_label = _load_text(source)
    records = [record for record in (_parse_line(line, idx + 1, source_label) for idx, line in enumerate(text.splitlines())) if record is not None]
    log_type = _resolve_log_type(records)
    return ParseResult(log_type=log_type, records=records, raw_text=text, source=source_label)


def _load_text(source: str | Path) -> tuple[str, str | None]:
    if isinstance(source, Path):
        if source.exists():
            return source.read_text(encoding="utf-8", errors="replace"), str(source)
        return str(source), None

    if "\n" not in source and "\r" not in source:
        path = Path(source)
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace"), str(path)

    return source, None


def _parse_line(line: str, line_no: int, source: str | None) -> LogRecord | None:
    stripped = line.strip()
    if not stripped:
        return None

    timestamp_raw, timestamp = _extract_timestamp(stripped)
    ip = _extract_ip(stripped)
    username = _extract_username(stripped)
    request_method, request_path = _extract_request(stripped)
    status_code = _extract_status_code(stripped)
    succeeded = _extract_success_flag(stripped, status_code, request_method)
    log_type = _detect_log_type(stripped, request_method, status_code)
    status = _derive_status(stripped, succeeded, status_code)
    alert_type = _extract_alert_type(stripped)
    device_name = _extract_device_name(stripped)
    key_values = _extract_key_values(stripped)

    fields: dict[str, str] = dict(key_values)
    if timestamp_raw:
        fields["time"] = timestamp_raw
    if ip:
        fields["ip"] = ip
    if username:
        fields["username"] = username
    if request_method:
        fields["request_method"] = request_method
    if request_path:
        fields["request_path"] = request_path
    if status_code is not None:
        fields["status_code"] = str(status_code)
    if alert_type:
        fields["alert_type"] = alert_type
    if device_name:
        fields["device_name"] = device_name

    return LogRecord(
        raw=stripped,
        line_no=line_no,
        source=source,
        log_type=log_type,
        timestamp=timestamp,
        timestamp_raw=timestamp_raw,
        username=username,
        account=username,
        ip=ip,
        status=status,
        succeeded=succeeded,
        request_method=request_method,
        request_path=request_path,
        status_code=status_code,
        alert_type=alert_type,
        device_name=device_name,
        event_description=stripped,
        fields=fields,
    )


def _extract_timestamp(line: str) -> tuple[str | None, datetime | None]:
    for pattern, formats in _TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        raw = match.group("value")
        for fmt in formats:
            try:
                parsed = datetime.strptime(raw, fmt)
            except ValueError:
                continue
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)
            return raw, parsed
    return None, None


def _extract_ip(line: str) -> str | None:
    match = _IPV4_RE.search(line)
    return match.group(0) if match else None


def _extract_username(line: str) -> str | None:
    for pattern in _USERNAME_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def _extract_request(line: str) -> tuple[str | None, str | None]:
    match = _METHOD_RE.search(line)
    if not match:
        return None, None
    method = match.group(1)
    path = match.group(2)
    return method, path


def _extract_status_code(line: str) -> int | None:
    match = _STATUS_CODE_RE.search(line)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _extract_success_flag(line: str, status_code: int | None, request_method: str | None) -> bool | None:
    lowered = line.lower()

    failure_markers = (
        "failed",
        "failure",
        "invalid",
        "denied",
        "reject",
        "refused",
        "blocked",
        "unauthorized",
        "authentication failure",
        "drop",
    )
    success_markers = (
        "accepted",
        "success",
        "logged in",
        "allow",
        "permitted",
        "authenticated",
        "login success",
    )

    if any(marker in lowered for marker in failure_markers):
        return False
    if any(marker in lowered for marker in success_markers):
        return True
    if status_code is not None and request_method:
        return status_code < 400
    if status_code is not None:
        return status_code < 400
    if "alert" in lowered:
        return None
    return None


def _derive_status(line: str, succeeded: bool | None, status_code: int | None) -> str | None:
    lowered = line.lower()
    if succeeded is True:
        return "success"
    if succeeded is False:
        return "failure"
    if "alert" in lowered:
        return "alert"
    if status_code is not None:
        return str(status_code)
    return None


def _detect_log_type(line: str, request_method: str | None, status_code: int | None) -> str:
    lowered = line.lower()
    if request_method:
        request = _extract_request(line)
        if request[1] and request[1].lower().startswith("/api"):
            return "api_access"
        return "web_access"
    if any(marker in lowered for marker in ("iot", "miio", "mihome", "xiaomi")) and any(
        marker in lowered for marker in ("device", "device_id=", "event", "telemetry", "offline", "online", "status=")
    ):
        return "iot_event"
    if "sshd" in lowered or "failed password" in lowered or "accepted password" in lowered:
        return "ssh_login"
    if "pam" in lowered or ("login" in lowered and any(marker in lowered for marker in ("failed", "success", "auth"))):
        return "system_login"
    if any(marker in lowered for marker in ("waf", "modsecurity")):
        return "waf_alert"
    if any(marker in lowered for marker in ("ids", "ips", "snort", "suricata")):
        return "ids_ips_alert"
    if any(marker in lowered for marker in ("firewall", "iptables", "deny", "drop", "block")) and status_code is None:
        return "firewall"
    if any(marker in lowered for marker in ("cloudtrail", "iam", "console login", "signin", "sign-in")):
        return "cloud_login"
    return "unknown"


def _extract_alert_type(line: str) -> str | None:
    lowered = line.lower()
    for marker in ("sql injection", "xss", "directory traversal", "command injection", "malware", "scan", "bruteforce"):
        if marker in lowered:
            return marker
    return None


def _extract_device_name(line: str) -> str | None:
    match = re.search(r"\b(?:device_id|device|host|sensor)=([^\s,;|]+)", line, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_key_values(line: str) -> dict[str, str]:
    return {match.group(1): match.group(2) for match in _KEY_VALUE_RE.finditer(line)}


def _resolve_log_type(records: Iterable[LogRecord]) -> str:
    counter = Counter(record.log_type for record in records if record.log_type != "unknown")
    if not counter:
        return "unknown"
    if len(counter) == 1:
        return next(iter(counter))
    most_common = counter.most_common(2)
    if most_common[0][1] > most_common[1][1]:
        return most_common[0][0]
    return "mixed"
