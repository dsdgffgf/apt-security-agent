from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .rag.schemas import RagHit


@dataclass(slots=True)
class CountItem:
    key: str
    count: int


@dataclass(slots=True)
class LogRecord:
    raw: str
    line_no: int | None = None
    source: str | None = None
    log_type: str = "unknown"
    timestamp: datetime | None = None
    timestamp_raw: str | None = None
    username: str | None = None
    account: str | None = None
    ip: str | None = None
    status: str | None = None
    succeeded: bool | None = None
    request_method: str | None = None
    request_path: str | None = None
    status_code: int | None = None
    alert_type: str | None = None
    device_name: str | None = None
    event_description: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParseResult:
    log_type: str
    records: list[LogRecord]
    raw_text: str
    source: str | None = None


@dataclass(slots=True)
class SummaryData:
    total_events: int
    success_events: int
    failure_events: int
    ip_count: int
    account_count: int
    top_ips: list[CountItem] = field(default_factory=list)
    top_accounts: list[CountItem] = field(default_factory=list)
    high_risk_accounts: list[CountItem] = field(default_factory=list)
    time_start: datetime | None = None
    time_end: datetime | None = None


@dataclass(slots=True)
class FailedLoginEvent:
    time: datetime | None
    ip: str | None
    account: str | None
    raw: str
    log_type: str | None = None


@dataclass(slots=True)
class FailedLoginStats:
    by_ip: list[CountItem]
    by_account: list[CountItem]
    events: list[FailedLoginEvent]


@dataclass(slots=True)
class Finding:
    kind: str
    description: str
    ip: str | None = None
    account: str | None = None
    count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskResult:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class StandardReference:
    framework: str
    code: str
    title: str
    severity_hint: str
    finding_kind: str = ""
    description: str = ""


@dataclass(slots=True)
class StandardsAssessment:
    references: list[StandardReference]
    risk: RiskResult
    summary: str
    evidence_points: list[str] = field(default_factory=list)
    retrieval_query: str = ""
    retrieved_context: list[RagHit] = field(default_factory=list)


@dataclass(slots=True)
class AgentJudgment:
    has_anomaly: bool
    suspected_attack: bool
    attack_types: list[str]
    attack_success_assessment: str
    false_positive_assessment: str
    evidence_sufficiency: str
    confidence: str
    tool_risk: RiskResult
    final_risk: RiskResult
    score_adjusted: bool = False
    adjustment_reason: str = "未调整 Python 风险提示。"
    standards_summary: str = ""
    standards_references: list[str] = field(default_factory=list)
    standards_consistency: str = "未记录行业标准"
    standards_risk: RiskResult | None = None
    analysis_path: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SecurityAnalysis:
    parse_result: ParseResult
    summary: SummaryData
    findings: list[Finding]
    selected_tools: list[str]
    tool_risk: RiskResult
    judgment: AgentJudgment
    failed_login_stats: FailedLoginStats | None = None
    source: str | None = None
    standards: StandardsAssessment | None = None
    tool_findings: dict[str, list[Finding]] = field(default_factory=dict)
    qwen_agent_used: bool = False
    agent_response: str | None = None
    agent_output: dict[str, Any] = field(default_factory=dict)


class AptPhase(str, Enum):
    """APT 攻击链阶段"""
    RECON = "recon"
    SOCIAL_ENG = "social_eng"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    LATERAL = "lateral"
    CROSS_TARGET = "cross_target"
    REPORT = "report"


@dataclass(slots=True)
class AptTarget:
    """APT 目标

    vector（决定攻击手段）:
      - firewall_breach: A — 互联网边界突破，攻破防火墙→内网扫描→横向移动
      - supply_chain:   B — 供应链跳板，利用已控乙方攻击丙方设备
      - phishing:       C — 大模型生成钓鱼邮件（中文习惯），控制设备
    """
    id: str
    host: str
    vector: str = "firewall_breach"
    compromised_via: str = ""
    discovered_ports: list[dict] = field(default_factory=list)
    discovered_services: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    compromised: bool = False
    access_level: str = "none"
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AptPhaseResult:
    """单阶段执行结果"""
    phase: AptPhase
    status: str = "pending"
    summary: str = ""
    findings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    llm_response: str = ""


@dataclass(slots=True)
class AptSimulationState:
    """全局 APT 状态"""
    targets: list[AptTarget]
    current_phase: AptPhase = AptPhase.RECON
    current_vector: str = "firewall_breach"
    phase_results: dict[str, AptPhaseResult] = field(default_factory=dict)
    blue_team_awareness: int = 0
    compromised_targets: list[str] = field(default_factory=list)
    kill_chain: list[dict] = field(default_factory=list)
    start_time: str = ""
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AptReport:
    """APT 最终报告"""
    title: str = "APT 攻击模拟报告"
    summary: str = ""
    targets: list[dict] = field(default_factory=list)
    phase_results: list[dict] = field(default_factory=list)
    kill_chain_summary: list[dict] = field(default_factory=list)
    critical_findings: list[str] = field(default_factory=list)
    hardening_recommendations: list[str] = field(default_factory=list)
    blue_team_awareness_analysis: str = ""
