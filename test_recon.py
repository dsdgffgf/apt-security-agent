"""Quick test: does LLM call web_content_fetch?"""
import json, sys
sys.path.insert(0, ".")

from security_log_analyzer.models import AptPhase, AptTarget, AptSimulationState
from security_log_analyzer.apt_core import PHASE_SYSTEM_PROMPTS, PHASE_TOOLS, build_phase_context
from security_log_analyzer.qwen_assistant import build_qwen_llm_config, create_qwen_security_assistant

target = AptTarget(id="t1", host="10.146.147.175")
state = AptSimulationState(targets=[target], current_vector="firewall_breach", blue_team_awareness=0)
state.current_phase = AptPhase.RECON

tools = PHASE_TOOLS[AptPhase.RECON]
system_prompt = PHASE_SYSTEM_PROMPTS[AptPhase.RECON]
system_prompt = f"{system_prompt}\n\n【你的目标 IP 是 {target.host}。所有工具调用的 target/host 参数必须填这个 IP。】"

target_info = {"target": target.host, "vector": "firewall_breach", "phase": "recon", "blue_team_awareness": 0, "phase_results": []}
user_prompt = build_phase_context(state, AptPhase.RECON) + "\n\n### 目标信息\n" + json.dumps(target_info, ensure_ascii=False, indent=2) + "\n\n请按 System Prompt 中的指引执行本阶段任务。"

print(f"Target: {target.host}")
print(f"Tools: {tools}")
print(f"Has web_content_fetch: {'web_content_fetch' in tools}")
print()

llm_cfg = build_qwen_llm_config(mode="apt")
assistant = create_qwen_security_assistant(system_message=system_prompt, mode="apt", function_list=tools, llm_cfg=llm_cfg)

print("Calling LLM...")
responses = assistant.run_nonstream([{"role": "user", "content": user_prompt}])

tools_called = []
for msg in responses:
    if isinstance(msg, dict):
        fc = msg.get("function_call", {}) or {}
        fn = fc.get("name", "") if isinstance(fc, dict) else ""
    else:
        fn = msg.function_call.name if msg.function_call else ""
    if fn:
        tools_called.append(fn)

print(f"\nTools called ({len(tools_called)}):")
for t in tools_called:
    print(f"  - {t}")

print(f"\nHas web_content_fetch: {'web_content_fetch' in tools_called}")
print(f"SUCCESS: {'web_content_fetch' in tools_called}")
