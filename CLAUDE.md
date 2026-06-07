# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.全程使用中文思考


## 运行命令

```bash
# CLI — 三种 APT 攻击向量 + 渗透测试 + 日志防御分析
python -m security_log_analyzer <目标> --mode apt --vector firewall   # 互联网边界突破
python -m security_log_analyzer <目标> --mode apt --vector supply     # 供应链跳板
python -m security_log_analyzer <目标> --mode apt --vector phishing   # 社工钓鱼
python -m security_log_analyzer <目标> --mode pentest                # 渗透测试
python -m security_log_analyzer <日志路径> --mode defense             # 日志安全分析

# APT 断点续跑 & C2 监听器
python -m security_log_analyzer <目标> --mode apt --resume
python -m security_log_analyzer.c2_listener --port 8080

# Web Dashboard (Flask + waitress + SSE 实时进度)
python web_dashboard/app.py              # http://127.0.0.1:5000
curl -X POST http://127.0.0.1:5000/api/apt/run \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","vector":"firewall_breach","mode":"real"}'

# 测试 (81 passed)
python -m pytest tests/ -q
```

## 架构概览

LLM 调用链路：`qwen-agent` 框架 → DeepSeek API (`deepseek-v4-pro` / `deepseek-v4-flash`)。API key 通过 `config.py` 从项目根目录 `.env` 自动加载。

### 核心模块

| 模块 | 职责 |
|------|------|
| `agentic.py` | 四模式入口 (`run_apt_agent`, `run_pentest_agent`, `run_attack_agent`, `run_security_agent_analysis`)，注入 system prompt + 工具列表创建 Agent |
| `apt_core.py` (~2900 行) | APT 仿真编排核心。`run_apt_simulation()` 按向量阶段序列驱动 `_execute_phase()`，每阶段统一走自动工具链 (`_auto_execute_phase_tools`) + 单次 LLM 分析 |
| `apt_tools.py` | APT 工具实现（nmap 封装、DNS 枚举、Web 攻击、UA/codename 爆破、SSH/SMB/FTP 凭证攻击、CVE 扫描等） |
| `exploitation.py` | 真实利用模块（弱口令爆破、SSH 隧道、内网扫描、SMB 枚举），依赖 paramiko/impacket |
| `tools.py` | 工具路由层。将所有 Python 函数注册为统一名字空间，`run_local_tool(name, params)` 分派调用，`run_local_tool_json()` 返回 JSON 字符串 |
| `qwen_assistant.py` | qwen-agent 框架桥接层。将工具注册为 FunctionTool，含参数 schema 和 deepseek tool_call_id monkey-patch |
| `models.py` | 防御侧 dataclass（`LogRecord`, `SummaryData`, `RiskResult` 等）和 APT 侧 dataclass（`AptPhase`, `AptTarget`, `AptSimulationState`, `AptPhaseResult`） |
| `config.py` | API 配置。`MODE_MODEL_MAP` 按模式选模型，`PHASE_MODELS` 按阶段选模型（工具驱动用 Flash，复杂分析用 Pro） |
| `report.py` | APT 仿真报告和防御分析报告生成 |
| `c2_listener.py` | 简易 C2 HTTP 服务器，社工钓鱼回传接收 |
| `rag/` | RAG 知识库（安全标准/漏洞情报检索），含 `corpus.py` 语料、`retriever.py` 检索、`schemas.py` 数据模型 |

### 三种攻击向量的阶段序列

| 向量 | 阶段 |
|------|------|
| `firewall_breach` | RECON → INITIAL_ACCESS → PERSISTENCE → LATERAL → REPORT |
| `supply_chain` | RECON → INITIAL_ACCESS → PERSISTENCE → CROSS_TARGET → REPORT |
| `phishing` | SOCIAL_ENG → INITIAL_ACCESS → PERSISTENCE → REPORT |

### 自动工具链执行流程

所有阶段统一走 `_auto_execute_phase_tools()` → 单次 LLM 分析，**LLM 不参与工具循环**（无 function call loop）：

1. **RECON**: socket 98 端口扫描 → HTTP 工具链（content_fetch / UA brute / codename brute / dir_enum）→ SMB 枚举 → FTP 匿名登录 → CVE 扫描
2. **INITIAL_ACCESS**: 基于 RECON 发现的端口执行针对性攻击（SSH 爆破、Web 攻击、SMB 枚举 + hash 破解）→ post-exploit（Verify → Expand → Harvest → Pivot）
3. **后续阶段**: 按 `PHASE_TOOLS[phase]` 列表逐个执行，结果注入 `state.notes` 供跨阶段传递

扫描结果缓存在 `state.notes["scan_cache"]` 和 `state.notes["open_ports"]`，后续阶段禁止重新扫描。

### Post-exploit 工作流

`_auto_initial_access()` 末尾自动执行四步后渗透：**Verify**（验证凭证对所有开放服务）→ **Expand**（SSH 远程执行侦察、SMB 认证枚举）→ **Harvest**（提取内网主机/用户/密码）→ **Pivot**（写入 `state.notes["credentials"]` 和 `state.notes["post_exploit"]`，设置 `target.compromised = True`）。

### Mock vs Real

`assistant_factory` 参数控制。传 `None` 走真实 DeepSeek API + 真实工具；传 `"mock"` 返回硬编码数据。Web dashboard 通过 POST body 的 `mode` 字段（`"real"` / `"mock"`）切换。

## 常见陷阱

- **Windows GBK 终端**: 使用 `safe_print()` 而非 `print()`（定义在 `apt_core.py` 和 `apt_tools.py`）
- **LLM 网络超时**: `_execute_phase()` 中 300s 超时后走 `_fallback_result()`，自动工具链结果不会丢失
- **ThreadPoolExecutor 关闭竞争**: `exploitation.py:credential_attack()` 中 executor 可能触发 `RuntimeError`，已加串行回退
- **端口扫描结果跨阶段共享**: 缓存到 `state.notes` 后，`build_phase_context()` 向所有阶段注入开放端口列表并附加"禁止重复扫描"指令
