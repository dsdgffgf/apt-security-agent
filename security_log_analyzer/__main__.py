from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

import sys

from .agent import analyze_security_logs
from .agentic import (
    SecurityAgentError,
    run_apt_agent,
    run_attack_agent,
    run_pentest_agent,
)
from .models import SecurityAnalysis
from .pentest_tools import WARNING_TEXT
from .report import build_apt_report, build_attack_report, build_pentest_report, build_security_report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="安全日志分析 / 渗透测试 / 攻击模拟 / APT 仿真 智能体")
    parser.add_argument("target", help="日志文件路径/目录/文本 (defense), 或目标 IP/域名 (pentest/attack/apt)")
    parser.add_argument(
        "--mode", choices=["defense", "pentest", "attack", "apt"], default="defense",
        help="运行模式：defense=日志安全分析 pentest=渗透测试 attack=攻击模拟研究 apt=APT 攻击模拟",
    )
    apt_opts = parser.add_argument_group("APT 模式专用选项")
    apt_opts.add_argument(
        "--vector", choices=["firewall", "supply", "phishing"], default="firewall",
        help="攻击向量：firewall=互联网边界突破 supply=供应链跳板 phishing=社工钓鱼",
    )
    apt_opts.add_argument(
        "--cross-target", default="",
        help="下游目标，supply_chain 向量先用主目标作跳板再攻击此目标",
    )
    apt_opts.add_argument(
        "--resume", action="store_true",
        help="从断点续跑，跳过已完成阶段",
    )
    parser.add_argument("--agent", action="store_true",
                        help="(等同 --mode defense) 使用 DeepSeek 智能体做最终研判")
    parser.add_argument(
        "--compare", action="store_true",
        help="(仅 defense) 同时运行本地+智能体分析并对比",
    )
    parser.add_argument("--source", help="(仅 defense) 日志文本的来源标签")
    args = parser.parse_args(argv)

    mode: str = args.mode
    if args.agent and mode == "defense":
        pass
    elif args.agent:
        print(f"警告: --agent 与 --mode {mode} 同时指定，以 --mode {mode} 为准", file=sys.stderr)

    if mode == "pentest":
        return _run_pentest_mode(args.target)
    if mode == "attack":
        return _run_attack_mode(args.target)
    if mode == "apt":
        return _run_apt_mode(args.target, args.vector, args.cross_target, resume=args.resume)

    target = _coerce_log_input(args.target)
    if args.compare:
        print(_render_compare_output(target, source=args.source))
        return 0
    if isinstance(target, Path) and target.is_dir():
        print(_render_batch_reports(target, use_agent=True))
        return 0
    analysis = _analyze_target(target, source=args.source, use_agent=True)
    print(_render_report(analysis))
    return 0


def _run_pentest_mode(target_spec: str) -> int:
    try:
        result = run_pentest_agent(target=target_spec)
    except SecurityAgentError as exc:
        print(f"渗透测试失败: {exc}", file=sys.stderr)
        return 1
    print(build_pentest_report(result))
    return 0


def _run_attack_mode(target_spec: str) -> int:
    target = target_spec if target_spec.strip() else None
    try:
        result = run_attack_agent(target=target)
    except SecurityAgentError as exc:
        print(f"攻击模拟失败: {exc}", file=sys.stderr)
        return 1
    print(build_attack_report(result))
    return 0


# CLI short names → internal vector keys
_VECTOR_MAP: dict[str, str] = {
    "firewall": "firewall_breach",
    "supply": "supply_chain",
    "phishing": "phishing",
}


def _run_apt_mode(target_spec: str, vector: str, cross_target: str = "", *, resume: bool = False) -> int:
    vector = _VECTOR_MAP.get(vector, vector)
    try:
        result = run_apt_agent(target=target_spec, vector=vector, cross_target=cross_target, resume=resume)
    except SecurityAgentError as exc:
        print(f"APT 攻击模拟失败: {exc}", file=sys.stderr)
        return 1
    report = build_apt_report(result)
    try:
        print(report)
    except UnicodeEncodeError:
        print(report.encode("gbk", errors="replace").decode("gbk"))
    return 0


def _coerce_log_input(value: str) -> str | Path:
    path = Path(value)
    if path.exists():
        return path
    return value


def _render_report(analysis: SecurityAnalysis) -> str:
    return build_security_report(
        summary=analysis.summary,
        findings=analysis.findings,
        risk=analysis.tool_risk,
        log_type=analysis.parse_result.log_type,
        source=analysis.source,
        selected_tools=analysis.selected_tools,
        judgment=analysis.judgment,
        failed_login_stats=analysis.failed_login_stats,
        tool_findings=analysis.tool_findings,
        standards=analysis.standards,
        qwen_agent_used=analysis.qwen_agent_used,
    )


def _render_batch_reports(directory: Path, *, use_agent: bool) -> str:
    blocks: list[str] = []
    for path in _iter_log_files(directory):
        try:
            analysis = _analyze_target(path, source=str(path), use_agent=use_agent)
        except Exception as exc:  # pragma: no cover - exercised in manual batch runs
            blocks.append(_render_error_block(path, "智能体" if use_agent else "本地", exc))
            continue
        blocks.append(_render_report(analysis))
    return "\n\n".join(blocks).rstrip()


def _render_compare_output(target: str | Path, *, source: str | None = None) -> str:
    if isinstance(target, Path) and target.is_dir():
        blocks: list[str] = ["# 批量对照结果", ""]
        for path in _iter_log_files(target):
            try:
                local = _analyze_target(path, source=str(path), use_agent=False)
            except Exception as exc:  # pragma: no cover - exercised in manual batch runs
                blocks.append(_render_error_block(path, "本地", exc))
                continue
            try:
                agent = _analyze_target(path, source=str(path), use_agent=True)
            except Exception as exc:  # pragma: no cover - exercised in manual batch runs
                blocks.append(_render_error_block(path, "智能体", exc))
                continue
            blocks.extend(_render_compare_block(path, local, agent))
        return "\n".join(blocks).rstrip()

    local = _analyze_target(target, source=source, use_agent=False)
    agent = _analyze_target(target, source=source, use_agent=True)
    return "\n".join(_render_compare_block(_target_label(target, source), local, agent)).rstrip()


def _render_compare_block(label: str | Path, local: SecurityAnalysis, agent: SecurityAnalysis) -> list[str]:
    local_risk = _final_risk(local)
    agent_risk = _final_risk(agent)
    local_attack = _attack_label(local)
    agent_attack = _attack_label(agent)
    delta = agent_risk.score - local_risk.score
    local_confidence = _confidence(local)
    agent_confidence = _confidence(agent)

    return [
        f"## {label}",
        f"- 本地：{local_risk.score}/{local_risk.level}，疑似攻击：{local_attack}，置信度：{local_confidence}",
        f"- 智能体：{agent_risk.score}/{agent_risk.level}，疑似攻击：{agent_attack}，置信度：{agent_confidence}",
        f"- 本地标准：{_standards_text(local)}",
        f"- 智能体标准：{_standards_text(agent)}",
        f"- 分差：{delta:+d}",
        "",
    ]


def _render_error_block(path: Path, mode: str, exc: Exception) -> str:
    return f"## {path}\n- {mode}分析失败：{exc}"


def _iter_log_files(directory: Path) -> list[Path]:
    log_files = sorted(
        (path for path in directory.rglob("*.log") if path.is_file()),
        key=lambda path: path.as_posix().lower(),
    )
    if not log_files:
        raise FileNotFoundError(f"No .log files found in directory: {directory}")
    return log_files


def _analyze_target(target: str | Path, *, source: str | None, use_agent: bool) -> SecurityAnalysis:
    effective_source = source
    if effective_source is None and isinstance(target, Path):
        effective_source = str(target)
    return analyze_security_logs(target, source=effective_source, qwen_agent_used=use_agent)


def _final_risk(analysis: SecurityAnalysis):
    if analysis.judgment is not None:
        return analysis.judgment.final_risk
    return analysis.tool_risk


def _attack_label(analysis: SecurityAnalysis) -> str:
    if analysis.judgment is None:
        return "否"
    return "是" if analysis.judgment.suspected_attack else "否"


def _confidence(analysis: SecurityAnalysis) -> str:
    if analysis.judgment is None:
        return "未知"
    return getattr(analysis.judgment, "confidence", None) or "未知"


def _standards_text(analysis: SecurityAnalysis) -> str:
    if analysis.standards is None:
        return "未提供"
    references = ", ".join(
        f"{reference.framework} {reference.code}" for reference in analysis.standards.references[:3]
    )
    if references:
        return f"{analysis.standards.summary}；{references}"
    return analysis.standards.summary or "未提供"


def _target_label(target: str | Path, source: str | None) -> str:
    if isinstance(target, Path):
        return str(target)
    return source or "原始文本"


if __name__ == "__main__":
    raise SystemExit(main())
