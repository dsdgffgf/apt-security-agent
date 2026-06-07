# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## 运行命令

```bash
# CLI — 四种模式
python -m security_log_analyzer <目标> --mode apt --vector firewall
python -m security_log_analyzer <目标> --mode apt --vector supply
python -m security_log_analyzer <目标> --mode apt --vector phishing
python -m security_log_analyzer <目标> --mode pentest
python -m security_log_analyzer <日志路径> --mode defense

# APT 断点续跑
python -m security_log_analyzer <目标> --mode apt --resume

# Web Dashboard
python web_dashboard/app.py   # http://127.0.0.1:5000
```

## 架构概览

LLM 调用链路：`qwen-agent` 框架 → DeepSeek API (`deepseek-v4-pro` / `deepseek-v4-flash`)。API key 通过 `config.py` 自动从项目根目录 `.env` 加载。

**核心模块：**

- `agentic.py` — 四个模式的入口函数 (`run_apt_agent`, `run_pentest_agent`, `run_attack_agent`, `run_security_agent_analysis`)，各自用 `create_qwen_security_assistant()` 创建 Agent，注入模式对应的 system prompt 和工具列表
- `apt_core.py` (~2000 行) — APT 仿真编排核心。`run_apt_simulation()` 按向量对应的阶段序列驱动 `_execute_phase()`；每个阶段可选择走 LLM 编排或自动工具链 (`_auto_recon`, `_auto_initial_access` 等)
- `apt_tools.py` — 所有攻击/侦察工具的 Python 实现（nmap 扫描、DNS 枚举、SSH 爆破、SMB 枚举、Web 攻击等）
- `qwen_assistant.py` — 桥接层。将本项目的 Python 工具注册为 qwen-agent 框架的 FunctionTool，包含工具参数 schema 和 monkey-patch （修复 deepseek tool_call_id 冲突）
- `config.py` — API 配置。`MODE_MODEL_MAP` 按模式选模型，`PHASE_MODELS` 按阶段选模型（工具驱动用 Flash，复杂分析用 Pro）
- `models.py` — 所有 dataclass 定义（`AptPhase`, `AptTarget`, `AptSimulationState`, `AptPhaseResult` 等）
- `web_dashboard/app.py` — Flask + waitress + SSE 实时进度推送。`EventCollector` 收集阶段事件，后台线程跑 APT 仿真

**三种攻击向量的阶段序列：**

| 向量 | 阶段 |
|------|------|
| `firewall_breach` | RECON → INITIAL_ACCESS → PERSISTENCE → LATERAL |
| `supply_chain` | RECON → INITIAL_ACCESS → PERSISTENCE → CROSS_TARGET |
| `phishing` | SOCIAL_ENG → INITIAL_ACCESS → PERSISTENCE |

**Post-exploit 工作流**（位于 `_auto_initial_access()` 末尾）：破解密码后自动执行 Verify → Expand → Harvest → Pivot 四步，将凭证和主机信息注入 `state.notes` 供后续 PERSISTENCE/LATERAL 阶段使用。

**Mock vs Real：** `assistant_factory` 参数控制。传 `None` 走真实 DeepSeek API + 真实工具；传 `"mock"` 返回硬编码数据。Web dashboard 通过 POST body 的 `mode` 字段切换。
