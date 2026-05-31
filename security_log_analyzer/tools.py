from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .detectors import detect_security_anomaly, risk_score
from .models import CountItem, Finding, LogRecord, RiskResult, SummaryData
from .parser import parse_log
from .apt_tools import (
    apt_boundary_scan,
    apt_credential_attack,
    apt_cross_plan,
    apt_cve_scan,
    apt_cve_verify,
    apt_docker_exploit,
    apt_evasion_plan,
    apt_exploit_plan,
    apt_lateral_plan,
    apt_log_clean,
    apt_nmap_nse_scan,
    apt_nmap_scan,
    apt_persistence_plan,
    apt_port_forward,
    apt_privilege_plan,
    apt_redis_exploit,
    apt_remote_exec,
    apt_report_gen,
    apt_smb_enum,
    apt_tunnel_establish,
    apt_web_poc,
    osint_recon,
    osint_social_recon,
    osint_tech_recon,
    se_conversation_gen,
    se_phishing_gen,
    web_content_fetch,
    web_user_agent_brute,
    web_codename_brute,
    web_login_brute,
    hash_extract,
    hash_crack,
)
from .pentest_tools import (
    attack_plan,
    bypass_test,
    dir_enum,
    form_detect,
    info_gather,
    injection_probe,
    payload_gen,
    pentest_report,
    port_scan,
    security_headers_check,
    service_detect,
    vuln_check,
    web_fingerprint,
)
from .stats import generate_summary_data


TOOL_NAMES = [
    "read_log_file",
    "parse_log",
    "summarize_log",
    "extract_basic_patterns",
    "risk_hint",
    "format_evidence",
    "port_scan",
    "service_detect",
    "dir_enum",
    "web_fingerprint",
    "vuln_check",
    "pentest_report",
    "payload_gen",
    "bypass_test",
    "info_gather",
    "attack_plan",
    "security_headers_check",
    "form_detect",
    "injection_probe",
    "osint_recon",
    "osint_tech_recon",
    "osint_social_recon",
    "se_phishing_gen",
    "se_conversation_gen",
    "apt_boundary_scan",
    "apt_exploit_plan",
    "apt_persistence_plan",
    "apt_log_clean",
    "apt_lateral_plan",
    "apt_privilege_plan",
    "apt_cross_plan",
    "apt_evasion_plan",
    "apt_report_gen",
    "apt_credential_attack",
    "apt_tunnel_establish",
    "apt_nmap_scan",
    "apt_smb_enum",
    "apt_web_poc",
    "apt_cve_scan",
    "apt_cve_verify",
    "apt_remote_exec",
    "apt_port_forward",
    "apt_nmap_nse_scan",
    "apt_redis_exploit",
    "apt_docker_exploit",
    "web_content_fetch",
    "web_user_agent_brute",
    "web_codename_brute",
    "web_login_brute",
    "hash_extract",
    "hash_crack",
]


def read_log_file(path: str | Path, *, encoding: str = "utf-8") -> str:
    log_path = Path(path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")
    if not log_path.is_file():
        raise IsADirectoryError(f"Log path is not a file: {log_path}")
    return log_path.read_text(encoding=encoding, errors="replace")


def summarize_log(records: list[LogRecord] | tuple[LogRecord, ...]) -> SummaryData:
    return generate_summary_data(records)


def extract_basic_patterns(records: list[LogRecord] | tuple[LogRecord, ...]) -> list[Finding]:
    return detect_security_anomaly(records)


def risk_hint(findings: Any, summary: SummaryData | dict[str, Any] | None = None) -> RiskResult:
    return risk_score(_coerce_findings(findings), _coerce_summary(summary))


def format_evidence(evidence: Any, *, limit: int = 5) -> dict[str, Any]:
    items = _collect_evidence_items(evidence)
    formatted = [_redact_sensitive(item) for item in items[:limit]]
    return {
        "formatted_evidence": formatted,
        "text": "；".join(formatted),
    }


def run_local_tool(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params or {}
    if name not in TOOL_NAMES:
        raise ValueError(f"Unknown tool: {name}")
    handler = _TOOL_DISPATCH.get(name)
    if handler is None:
        raise ValueError(f"No handler for tool: {name}")
    return handler(params)


def _p(params: dict[str, Any], key: str, default: Any = "") -> Any:
    """Extract param from multiple possible keys (precise match then fallback)"""
    return params.get(key) or params.get(key.replace("_", "-")) or default


# ── Tool dispatch table ───────────────────────────────

_TOOL_DISPATCH: dict[str, Any] = {}

def _register(name: str):
    """Decorator to register a tool handler"""
    def wrapper(fn):
        _TOOL_DISPATCH[name] = fn
        return fn
    return wrapper


# ── Defense tools ─────────────────────────────────────

@_register("read_log_file")
def _hdl_read_log(params):
    path = params.get("path") or params.get("log_input") or params.get("file_path")
    if not path:
        raise ValueError("read_log_file requires 'path' parameter.")
    return {"log_text": read_log_file(path)}

def _log_input(params):
    return params.get("log_input") or params.get("text") or params.get("content") or ""

def _parse_and_records(params):
    log_input = _log_input(params)
    parsed = parse_log(log_input)
    return parsed, parsed.records

@_register("parse_log")
def _hdl_parse_log(params):
    parsed, _ = _parse_and_records(params)
    return _to_jsonable(parsed)

@_register("summarize_log")
def _hdl_summarize_log(params):
    _, records = _parse_and_records(params)
    return _to_jsonable(summarize_log(records))

@_register("extract_basic_patterns")
def _hdl_extract(params):
    _, records = _parse_and_records(params)
    return {"findings": _to_jsonable(extract_basic_patterns(records))}

@_register("risk_hint")
def _hdl_risk_hint(params):
    if "log_input" in params:
        _, records = _parse_and_records(params)
        return _to_jsonable(risk_hint(extract_basic_patterns(records), summarize_log(records)))
    return _to_jsonable(risk_hint(params.get("findings", []), params.get("summary")))

@_register("format_evidence")
def _hdl_format_evidence(params):
    evidence = params.get("evidence", params.get("findings", params.get("items", [])))
    return format_evidence(evidence, limit=int(params.get("limit", 5)))


# ── Pentest tools ────────────────────────────────────

def _target(params):
    return params.get("target", "")

def _ports(params):
    ports = params.get("ports")
    return [int(p) for p in ports] if ports else None

@_register("port_scan")
def _hdl_port_scan(params):
    from .pentest_tools import validate_target
    err = validate_target(_target(params))
    if err:
        return {"error": err}
    return port_scan(_target(params), _ports(params))

@_register("service_detect")
def _hdl_service_detect(params):
    return service_detect(_target(params), _ports(params))

@_register("dir_enum")
def _hdl_dir_enum(params):
    return dir_enum(_target(params))

@_register("web_fingerprint")
def _hdl_web_fingerprint(params):
    return web_fingerprint(_target(params))

@_register("vuln_check")
def _hdl_vuln_check(params):
    return vuln_check(params.get("services"), params.get("fingerprint"))

@_register("pentest_report")
def _hdl_pentest_report(params):
    return pentest_report(params.get("findings"), target=_target(params))


# ── Attack tools ─────────────────────────────────────

@_register("payload_gen")
def _hdl_payload_gen(params):
    return payload_gen(params.get("attack_type", "sqli"), count=int(params.get("count", 5)))

@_register("bypass_test")
def _hdl_bypass_test(params):
    return bypass_test(params.get("payload", ""), params.get("target_encoding", "url"))

@_register("info_gather")
def _hdl_info_gather(params):
    return info_gather(_target(params))

@_register("attack_plan")
def _hdl_attack_plan(params):
    return attack_plan(params.get("target_info"))


# ── Web security tools ───────────────────────────────

@_register("security_headers_check")
def _hdl_sec_headers(params):
    return security_headers_check(_target(params))

@_register("form_detect")
def _hdl_form_detect(params):
    return form_detect(_target(params))

@_register("injection_probe")
def _hdl_injection_probe(params):
    return injection_probe(_target(params), params.get("param"))


# ── OSINT/Social tools ──────────────────────────────

@_register("osint_recon")
def _hdl_osint_recon(params):
    return osint_recon(_target(params))

@_register("osint_tech_recon")
def _hdl_tech_recon(params):
    return osint_tech_recon(_target(params))

@_register("osint_social_recon")
def _hdl_social_recon(params):
    return osint_social_recon(_target(params))

@_register("se_phishing_gen")
def _hdl_phishing(params):
    return se_phishing_gen(params.get("context", {}))

@_register("se_conversation_gen")
def _hdl_conversation(params):
    return se_conversation_gen(params.get("context", {}))


# ── APT tools ────────────────────────────────────────

@_register("apt_boundary_scan")
def _hdl_boundary_scan(params):
    return apt_boundary_scan(_target(params), **{k: v for k, v in params.items() if k != "target"})

@_register("apt_exploit_plan")
def _hdl_exploit_plan(params):
    return apt_exploit_plan(params.get("scan_results", {}))

@_register("apt_persistence_plan")
def _hdl_persistence(params):
    return apt_persistence_plan(params.get("target_info", {}))

@_register("apt_log_clean")
def _hdl_log_clean(params):
    return apt_log_clean(params.get("target_info", {}))

def _apt_state(params):
    """Extract APT state dict from params (JSON string or dict)"""
    raw = params.get("state", {})
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}

@_register("apt_lateral_plan")
def _hdl_lateral(params):
    return apt_lateral_plan(_apt_state(params))

@_register("apt_privilege_plan")
def _hdl_privilege(params):
    return apt_privilege_plan(_apt_state(params))

@_register("apt_cross_plan")
def _hdl_cross(params):
    return apt_cross_plan(_apt_state(params))

@_register("apt_evasion_plan")
def _hdl_evasion(params):
    return apt_evasion_plan(_apt_state(params))

@_register("apt_report_gen")
def _hdl_apt_report(params):
    return apt_report_gen(_apt_state(params))

@_register("apt_credential_attack")
def _hdl_cred_attack(params):
    return apt_credential_attack(
        params.get("host", _target(params)),
        services=params.get("services"),
        **{k: v for k, v in params.items() if k not in ("host", "target", "services")},
    )

@_register("apt_tunnel_establish")
def _hdl_tunnel(params):
    return apt_tunnel_establish(
        params.get("host", _target(params)),
        params.get("username", ""),
        params.get("password", ""),
        **{k: v for k, v in params.items() if k not in ("host", "target", "username", "password")},
    )

@_register("apt_nmap_scan")
def _hdl_nmap_scan(params):
    return apt_nmap_scan(
        _target(params),
        ports=params.get("ports", "1-1000"),
        **{k: v for k, v in params.items() if k not in ("target", "ports")},
    )

@_register("apt_smb_enum")
def _hdl_smb_enum(params):
    return apt_smb_enum(
        params.get("host", _target(params)),
        **{k: v for k, v in params.items() if k not in ("host", "target")},
    )

@_register("apt_web_poc")
def _hdl_web_poc(params):
    return apt_web_poc(
        _target(params),
        port=int(params.get("port", 80)),
        **{k: v for k, v in params.items() if k not in ("target", "port")},
    )

@_register("web_content_fetch")
def _hdl_web_content(params):
    return web_content_fetch(
        _target(params),
        port=int(params.get("port", 80)),
        **{k: v for k, v in params.items() if k not in ("target", "port")},
    )

@_register("apt_cve_scan")
def _hdl_cve_scan(params):
    return apt_cve_scan(params.get("services", []))

@_register("apt_cve_verify")
def _hdl_cve_verify(params):
    return apt_cve_verify(
        _target(params),
        params.get("cve_id", ""),
        port=int(params.get("port", 80)),
        **{k: v for k, v in params.items() if k not in ("target", "cve_id", "port")},
    )

@_register("apt_remote_exec")
def _hdl_remote_exec(params):
    return apt_remote_exec(
        params.get("host", _target(params)),
        params.get("username", ""),
        params.get("password", ""),
        params.get("command", ""),
        **{k: v for k, v in params.items() if k not in ("host", "target", "username", "password", "command")},
    )

@_register("apt_port_forward")
def _hdl_port_forward(params):
    return apt_port_forward(
        params.get("host", _target(params)),
        params.get("username", ""),
        params.get("password", ""),
        params.get("remote_host", ""),
        int(params.get("remote_port", 0)),
        **{k: v for k, v in params.items() if k not in ("host", "target", "username", "password", "remote_host", "remote_port")},
    )

@_register("apt_nmap_nse_scan")
def _hdl_nse_scan(params):
    return apt_nmap_nse_scan(_target(params), **{k: v for k, v in params.items() if k != "target"})

@_register("apt_redis_exploit")
def _hdl_redis(params):
    return apt_redis_exploit(_target(params), port=int(params.get("port", 6379)),
                             **{k: v for k, v in params.items() if k not in ("target", "port")})

@_register("apt_docker_exploit")
def _hdl_docker(params):
    return apt_docker_exploit(_target(params), port=int(params.get("port", 2375)),
                              **{k: v for k, v in params.items() if k not in ("target", "port")})

@_register("web_user_agent_brute")
def _hdl_ua_brute(params):
    return web_user_agent_brute(
        _target(params),
        port=int(params.get("port", 80)),
        **{k: v for k, v in params.items() if k not in ("target", "port")},
    )

@_register("web_codename_brute")
def _hdl_codename_brute(params):
    return web_codename_brute(
        _target(params),
        port=int(params.get("port", 80)),
        wordlist=params.get("wordlist"),
        **{k: v for k, v in params.items() if k not in ("target", "port", "wordlist")},
    )

@_register("web_login_brute")
def _hdl_login_brute(params):
    return web_login_brute(
        _target(params),
        port=int(params.get("port", 80)),
        usernames=params.get("usernames"),
        passwords=params.get("passwords"),
        **{k: v for k, v in params.items() if k not in ("target", "port", "usernames", "passwords")},
    )

@_register("hash_extract")
def _hdl_hash_extract(params):
    return hash_extract(
        content=params.get("content", ""),
        **{k: v for k, v in params.items() if k != "content"},
    )

@_register("hash_crack")
def _hdl_hash_crack(params):
    return hash_crack(
        hashes=params.get("hashes", []),
        **{k: v for k, v in params.items() if k != "hashes"},
    )


def run_local_tool_json(name: str, params_json: str) -> str:
    params = json.loads(params_json) if params_json else {}
    return json.dumps(run_local_tool(name, params), ensure_ascii=False, sort_keys=True)


def _ensure_dict(value: Any) -> dict[str, Any]:
    """JSON 字符串转 dict"""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return {}


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_to_jsonable(item) for item in value]
    return value


def _coerce_findings(value: Any) -> list[Finding]:
    if value is None:
        return []
    if isinstance(value, dict) and "findings" in value:
        return _coerce_findings(value["findings"])
    if isinstance(value, Finding):
        return [value]
    if isinstance(value, list | tuple):
        return [_coerce_finding(item) for item in value]
    return []


def _coerce_finding(value: Any) -> Finding:
    if isinstance(value, Finding):
        return value
    if not isinstance(value, dict):
        return Finding(kind="unknown", description=str(value))
    return Finding(
        kind=str(value.get("kind") or "unknown"),
        description=str(value.get("description") or value.get("kind") or "unknown"),
        ip=value.get("ip"),
        account=value.get("account"),
        count=int(value.get("count") or 0),
        evidence=[str(item) for item in value.get("evidence", [])],
        details=dict(value.get("details") or {}),
    )


def _coerce_summary(value: SummaryData | dict[str, Any] | None) -> SummaryData | None:
    if value is None or isinstance(value, SummaryData):
        return value
    if not isinstance(value, dict):
        return None
    return SummaryData(
        total_events=int(value.get("total_events") or 0),
        success_events=int(value.get("success_events") or 0),
        failure_events=int(value.get("failure_events") or 0),
        ip_count=int(value.get("ip_count") or 0),
        account_count=int(value.get("account_count") or 0),
        high_risk_accounts=_coerce_count_items(value.get("high_risk_accounts", [])),
    )


def _coerce_count_items(value: Any) -> list[CountItem]:
    if not isinstance(value, list | tuple):
        return []
    items: list[CountItem] = []
    for item in value:
        if isinstance(item, CountItem):
            items.append(item)
        elif isinstance(item, dict):
            items.append(CountItem(key=str(item.get("key") or ""), count=int(item.get("count") or 0)))
    return items


def _collect_evidence_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Finding):
        return list(value.evidence)
    if isinstance(value, dict):
        if "findings" in value:
            return _collect_evidence_items(value["findings"])
        if "evidence" in value:
            return _collect_evidence_items(value["evidence"])
        if "raw" in value:
            return [str(value["raw"])]
        return [json.dumps(_to_jsonable(value), ensure_ascii=False, sort_keys=True)]
    if isinstance(value, list | tuple):
        items: list[str] = []
        for item in value:
            items.extend(_collect_evidence_items(item))
        return items
    return [str(value)]


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
