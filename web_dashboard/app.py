"""APT 攻击模拟可视化管理系统 — Flask 后端"""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

# 确保项目根目录在 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from security_log_analyzer.apt_core import (
    PHASE_LABELS,
    VECTOR_LABELS,
    VECTOR_PHASES,
    run_apt_simulation,
)
from security_log_analyzer.models import AptPhase
from security_log_analyzer.report import build_apt_report

app = Flask(__name__)

# ── 全局状态 ──────────────────────────────────────────────
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()

VECTOR_ORDER: list[tuple[str, str, str]] = [
    ("firewall_breach", "A", "🛡️"),
    ("supply_chain", "B", "🔗"),
    ("phishing", "C", "🎣"),
]


# ── Event collector ───────────────────────────────────────

class EventCollector:
    """收集阶段事件，转为 SSE 事件流"""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self._events: list[dict] = []
        self._start_time = time.time()

    def emit(self, event_type: str, data: dict | str) -> None:
        self._events.append({
            "type": event_type,
            "data": data if isinstance(data, dict) else {"text": data},
            "ts": time.time(),
        })

    def emit_phase_start(self, phase: AptPhase) -> None:
        elapsed = time.time() - self._start_time
        self.emit("phase_start", {
            "phase": phase.value,
            "label": PHASE_LABELS.get(phase, phase.value),
            "elapsed": round(elapsed, 1),
        })

    def emit_phase_done(self, phase: AptPhase, summary: str, findings: list[str],
                        *, elapsed: float = 0, cumulative: float = 0) -> None:
        self.emit("phase_done", {
            "phase": phase.value,
            "label": PHASE_LABELS.get(phase, phase.value),
            "summary": summary,
            "findings": findings[:5],
            "elapsed": round(elapsed, 1),
            "cumulative": round(cumulative, 1),
        })

    def emit_log(self, text: str) -> None:
        self.emit("log", {"text": text.strip()})

    def emit_error(self, text: str) -> None:
        self.emit("error", {"text": text})

    def emit_done(self, awareness: int) -> None:
        self.emit("done", {"awareness": awareness})

    def get_events(self) -> list[dict]:
        return list(self._events)


# ── 仿真执行器 ─────────────────────────────────────────────

def _run_simulation_with_events(
    job_id: str,
    target_host: str,
    vector: str,
    collector: EventCollector,
    cross_host: str = "",
    assistant_factory: Any = "mock",
    resume: bool = False,
) -> dict[str, Any]:
    """执行 APT 仿真，通过 collector 推送事件"""
    if assistant_factory == "mock":
        from demo_apt import mock_assistant_factory as factory
    elif assistant_factory is None:
        factory = None  # real mode — _execute_phase will create real assistants
    else:
        factory = assistant_factory

    try:
        result = _run_with_event_hooks(target_host, vector, collector, factory, cross_host, resume=resume)
        collector.emit_done(result["state"]["blue_team_awareness"])
        return result
    except Exception as exc:
        collector.emit_error(str(exc))
        raise


def _run_with_event_hooks(
    target_host: str,
    vector: str,
    collector: EventCollector,
    assistant_factory: Any,
    cross_host: str = "",
    resume: bool = False,
) -> dict[str, Any]:
    from security_log_analyzer.agentic import SecurityAgentError
    from security_log_analyzer.apt_core import (
        _build_final_result,
        _execute_phase,
        build_initial_state,
        load_checkpoint,
        merge_phase_result,
        save_checkpoint,
        _restore_state_from_checkpoint,
    )
    import time as _time

    _phase_timings: dict[str, float] = {}
    _overall_start = _time.monotonic()
    completed_phases: set[str] = set()

    if resume:
        ck = load_checkpoint()
        if ck:
            state = _restore_state_from_checkpoint(ck)
            phases = VECTOR_PHASES.get(state.current_vector, VECTOR_PHASES["firewall_breach"])
            completed_phases = set(ck.get("phase_results", {}).keys())
            _phase_timings = ck.get("phase_timings", {})
            collector.emit_log(f"[断点续跑] 目标: {state.targets[0].host}")
            collector.emit_log(f"已完成: {', '.join(PHASE_LABELS.get(AptPhase(p), p) for p in completed_phases if p != 'report')}")
            creds = state.notes.get("credentials")
            if creds:
                collector.emit_log(f"已有凭证: {creds.get('username', '?')}:{creds.get('password', '?')}")
        else:
            collector.emit_log("未找到断点文件，开始全新模拟。")
            resume = False

    if not resume:
        target = {"id": f"target_{uuid.uuid4().hex[:6]}", "host": target_host, "vector": vector}
        if cross_host and vector == "supply_chain":
            target["cross_host"] = cross_host
            target["cross_id"] = f"cross_{uuid.uuid4().hex[:4]}"
        state = build_initial_state(target)
        phases = VECTOR_PHASES.get(vector, VECTOR_PHASES["firewall_breach"])

    mode_name = "REAL" if assistant_factory is None else "MOCK"
    collector.emit_log(f"[{mode_name}] 攻击向量: {VECTOR_LABELS.get(vector, vector)}")
    collector.emit_log(f"目标: {target_host}")
    if cross_host:
        collector.emit_log(f"跳板攻击下游: {cross_host} (通过已控 {target_host})")
    collector.emit_log(f"阶段: {' → '.join(PHASE_LABELS[p] for p in phases)} → 报告生成")

    for phase in phases:
        if state.blue_team_awareness >= 90:
            collector.emit_log(f"蓝队感知度过高 ({state.blue_team_awareness}/100)，攻击链终止")
            break

        if phase.value in completed_phases:
            collector.emit_log(f"[跳过] {PHASE_LABELS.get(phase, phase.value)} (已完成)")
            continue

        state.current_phase = phase
        collector.emit_phase_start(phase)
        _t0 = _time.monotonic()

        try:
            result = _execute_phase(state, phase, assistant_factory)
            _elapsed = _time.monotonic() - _t0
            _cumul = _time.monotonic() - _overall_start
            _phase_timings[phase.value] = _elapsed
            merge_phase_result(state, phase, result)
            icon = "[OK]" if result.get("summary") else "[FAIL]"
            collector.emit_log(f"{icon} {result.get('summary', '完成')}")
            collector.emit_phase_done(phase, result.get("summary", ""), result.get("findings", []),
                                      elapsed=_elapsed, cumulative=_cumul)
            save_checkpoint(state, _phase_timings)
        except SecurityAgentError as exc:
            _phase_timings[phase.value] = _time.monotonic() - _t0
            collector.emit_error(f"阶段 {PHASE_LABELS.get(phase, phase.value)} 执行失败: {exc}")
            save_checkpoint(state, _phase_timings)
            break

    # 报告阶段
    if "report" not in completed_phases:
        state.current_phase = AptPhase.REPORT
        collector.emit_phase_start(AptPhase.REPORT)
        _t0 = _time.monotonic()
        try:
            result = _execute_phase(state, AptPhase.REPORT, assistant_factory)
            _elapsed = _time.monotonic() - _t0
            _cumul = _time.monotonic() - _overall_start
            merge_phase_result(state, AptPhase.REPORT, result)
            collector.emit_phase_done(AptPhase.REPORT, result.get("summary", ""), result.get("findings", []),
                                      elapsed=_elapsed, cumulative=_cumul)
        except SecurityAgentError:
            pass
        save_checkpoint(state, _phase_timings)

    return _build_final_result(state)


# ── Routes ─────────────────────────────────────────────────

@app.route("/")
def index() -> str:
    return render_template("index.html", vectors=[
        {
            "key": k,
            "letter": letter,
            "emoji": emoji,
            "label": VECTOR_LABELS[k],
            "phases": [PHASE_LABELS[p] for p in VECTOR_PHASES.get(k, [])],
            "prime_target": {
                "firewall_breach": "面向公网的目标（高校/企业官网）",
                "supply_chain": "已控乙方跳板可达的下游目标",
                "phishing": "教育/政府/事业单位（有 OA 和邮件系统）",
            }[k],
        }
        for k, letter, emoji in VECTOR_ORDER
    ])


@app.route("/api/apt/run", methods=["POST"])
def api_apt_run() -> Response:
    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    vector = (body.get("vector") or "firewall_breach").strip()
    cross_target = (body.get("cross_target") or "").strip()
    use_real = (body.get("mode") or "real") == "real"
    use_resume = body.get("resume", False)

    if not target:
        return jsonify({"error": "请提供目标地址"}), 400
    if vector not in VECTOR_PHASES:
        return jsonify({"error": f"未知向量: {vector}"}), 400

    job_id = uuid.uuid4().hex[:12]
    started = time.strftime("%Y-%m-%d %H:%M:%S")

    collector = EventCollector(job_id)
    assistant_factory = None if use_real else "mock"  # None = real DeepSeek API

    with _jobs_lock:
        _jobs[job_id] = {
            "status": "running",
            "vector": vector,
            "target": target,
            "cross_target": cross_target,
            "started": started,
            "collector": collector,
            "result": None,
            "mode": "real" if use_real else "mock",
        }

    def _run_in_thread() -> None:
        try:
            result = _run_simulation_with_events(
                job_id, target, vector, collector, cross_target,
                assistant_factory=assistant_factory, resume=use_resume,
            )
            status = "done"
        except Exception:
            result = None
            status = "failed"
        with _jobs_lock:
            job = _jobs.get(job_id, {})
            job["status"] = status
            job["result"] = result
            job["events"] = collector.get_events()  # snapshot for non-SSE access

    t = threading.Thread(target=_run_in_thread, daemon=False)
    t.start()

    return jsonify({
        "job_id": job_id,
        "status": "running",
        "mode": "real" if use_real else "mock",
    })


@app.route("/api/apt/stream/<job_id>")
def api_apt_stream(job_id: str) -> Response:
    def _stream() -> Any:
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            yield f"data: {json.dumps({'type': 'error', 'data': {'text': '任务不存在'}})}\n\n"
            return

        collector = job.get("collector")
        sent = 0
        # Poll for up to 10 minutes (real mode can be slow)
        for _ in range(6000):
            events = collector.get_events() if collector else job.get("events", [])
            while sent < len(events):
                ev = events[sent]
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                sent += 1
                # Brief delay for animation in mock mode
                time.sleep(0.02)

            with _jobs_lock:
                status = job.get("status", "running")
            if status in ("done", "failed"):
                yield f"data: {json.dumps({'type': 'status', 'data': {'status': status}}, ensure_ascii=False)}\n\n"
                return

            time.sleep(0.2)  # poll interval for new events

    return Response(
        stream_with_context(_stream()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/apt/report/<job_id>")
def api_apt_report(job_id: str) -> Response:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    if job["status"] != "done":
        return jsonify({"status": job["status"], "message": "任务尚未完成"}), 202

    result = job.get("result")
    if not result:
        return jsonify({"error": "无结果数据"}), 500

    try:
        report = build_apt_report(result)
    except Exception:
        report = "报告生成失败"

    return jsonify({
        "job_id": job_id,
        "target": job["target"],
        "vector": job["vector"],
        "vector_label": VECTOR_LABELS.get(job["vector"], job["vector"]),
        "started": job["started"],
        "state": result.get("state", {}),
        "phase_results": result.get("phase_results", []),
        "report": report,
        "mode": job.get("mode", "mock"),
    })


@app.route("/api/apt/history")
def api_apt_history() -> Response:
    items = []
    with _jobs_lock:
        for jid, job in _jobs.items():
            items.append({
                "job_id": jid,
                "target": job["target"],
                "vector": VECTOR_LABELS.get(job["vector"], job["vector"]),
                "status": job["status"],
                "started": job["started"],
                "mode": job.get("mode", "mock"),
            })
    items.sort(key=lambda x: x["started"], reverse=True)
    return jsonify(items)


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="127.0.0.1", port=5000, threads=8)
