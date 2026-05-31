"""APT 攻击模拟 — 三种向量独立演示（无 API 依赖）"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

sys.path.insert(0, ".")

# ── 三种向量的模拟响应 ─────────────────────────────────────
# 结构: { vector: { phase: response_dict } }

MOCK_RESPONSES: dict[str, dict[str, dict[str, Any]]] = {
    # ═══ A — 互联网边界突破 ═══
    "firewall_breach": {
        "recon": {
            "summary": "目标情报收集完成 — 发现公网防火墙和 VPN 入口",
            "findings": [
                "目标 IP: 203.0.113.10，开放端口 22/443/8443/10443",
                "检测到华为 USG 防火墙，管理口 HTTPS(8443) 暴露在公网",
                "子域名: www/mail/vpn/oa，邮箱格式: name@a-org.edu.cn",
                "组织架构: 校长办公室、信息中心、财务处、各院系",
            ],
            "osint_result": {"ip": "203.0.113.10", "subdomains": ["www", "mail", "vpn", "oa"]},
            "tech_result": {"detected_techs": ["Apache/2.4", "PHP/7.4"], "waf_type": "华为 WAF"},
            "social_result": {"organization": "A 大学", "key_personnel": [{"role": "校长", "name": "张"}]},
            "blue_team_awareness_delta": 5,
        },
        "initial_access": {
            "summary": "防火墙突破方案 — 华为 USG HTTPS 管理口弱口令可尝试",
            "findings": [
                "华为 USG 防火墙管理口 (TCP 8443) 使用默认口令 admin/Huawei@123",
                "VPN (SSL VPN, TCP 443) 存在 CVE-2024-XXXX 未授权访问漏洞",
                "推荐路径: 防火墙弱口令 → VPN 权限提升 → 内网接入",
            ],
            "scan_result": {"open_ports": [22, 25, 80, 443, 8443, 10443], "vpn_detected": True},
            "exploit_result": {"entry_points": [{"method": "防火墙弱口令", "success_probability": "80%"}]},
            "firewall_info": {"detected": True, "brand": "华为 USG", "mgmt_ports": ["8443", "10443"]},
            "blue_team_awareness_delta": 15,
        },
        "persistence": {
            "summary": "持久化方案 — 建立 SOCKS5 隧道 + 定时任务回调",
            "findings": [
                "通过防火墙 NAT 规则添加端口映射，维持外部 C2 通道",
                "在运维跳板机写入 crontab 每 5 分钟反向连接",
                "清理 /var/log/auth.log 中登录记录",
            ],
            "persistence_result": {"methods": ["SOCKS5 隧道", "crontab 回调"]},
            "log_clean_result": {"cleaned": ["auth.log", "bash_history"]},
            "blue_team_awareness_delta": 20,
        },
        "lateral": {
            "summary": "内网横向移动 — 发现 4 个网段，定位域控和核心数据库",
            "findings": [
                "内网拓扑: 办公区(10.0.0.0/24)、服务器区(10.0.1.0/24)、数据中心(10.0.10.0/24)、DMZ(10.0.254.0/24)",
                "高价值资产: 域控 AD(10.0.1.10)、Oracle 数据库(10.0.10.50)、文件服务器(10.0.1.20)",
                "域控存在 MS17-010 未修复，可通过 SMB 横向",
            ],
            "lateral_result": {"segments": 4, "high_value_assets": 3},
            "privilege_result": {"methods": ["MS17-010", "Kerberoasting"]},
            "asset_inventory": [
                {"host": "10.0.1.10", "role": "域控 AD", "os": "Windows Server 2016"},
                {"host": "10.0.10.50", "role": "Oracle 数据库", "os": "RHEL 7"},
            ],
            "blue_team_awareness_delta": 20,
        },
        "report": {
            "summary": "A 向量 — 互联网边界突破攻击链报告已生成",
            "findings": [
                "完整攻击链: internet → 华为USG弱口令 → 内网 → 域控+数据库",
                "蓝队感知度: 60/100，攻击全程未被有效发现",
                "关键脆弱性: 防火墙默认口令、VPN 未授权访问、内网 SMB 漏洞",
            ],
            "report_result": {
                "critical_findings": [
                    "[!] 华为 USG 防火墙使用默认口令 admin/Huawei@123",
                    "[!] SSL VPN 存在 CVE-2024-XXXX 未授权访问",
                    "[!] 域控未修复 MS17-010",
                ],
                "hardening_recommendations": [
                    "立即修改防火墙默认口令，关闭管理口公网可达",
                    "升级 SSL VPN 至最新版本",
                    "对域控进行补丁修复，实施内网段隔离",
                    "部署堡垒机 + MFA 双因子认证",
                ],
            },
            "blue_team_awareness_delta": 0,
        },
    },

    # ═══ B — 供应链跳板 ═══
    "supply_chain": {
        "recon": {
            "summary": "供应链跳板侦察 — 识别已控乙方 B 与丙方 C 的信任关系",
            "findings": [
                "乙方 B: b-tech.com.cn (IP: 10.200.1.1)，已获得运维权限",
                "丙方 C: c-manufacturing.com (IP: 192.168.50.1)，从 B 内网可达",
                "B 与 C 之间存在 VPN 专线（深信服设备），用于远程运维",
                "C 为制造业企业，B 是其 IT 外包服务商",
            ],
            "osint_result": {"ip": "192.168.50.1", "reachable_from": "B 内网"},
            "tech_result": {"detected_techs": ["深信服 AF"], "waf_type": "深信服 WAF"},
            "social_result": {"organization": "C 制造有限公司", "relationship": "B 的 IT 外包客户"},
            "blue_team_awareness_delta": 5,
        },
        "initial_access": {
            "summary": "跳板突破 — 利用 B 的 VPN 配置直接接入 C 内网",
            "findings": [
                "在 B 运维终端上发现 C 的深信服 VPN 配置文件（含预共享密钥）",
                "从 B 内网通过 VPN 隧道接入 C，流量标记为正常运维通道",
                "C 防火墙管理口 8443 从隧道内可达，使用默认运维口令",
            ],
            "scan_result": {"open_ports": [22, 443, 8443], "vpn_detected": True, "from_springboard": True},
            "exploit_result": {"entry_points": [{"method": "VPN 配置文件窃取 + 预共享密钥", "difficulty": "低"}]},
            "via_target": "b-tech.com.cn",
            "blue_team_awareness_delta": 15,
        },
        "persistence": {
            "summary": "跳板持久化 — 在 B 和 C 防火墙上创建隐藏管理账号",
            "findings": [
                "在 B 深信服 AF 上创建隐藏管理员账号 audit_service",
                "在 C 防火墙 SNMP 写入读写团体字作为备用通道",
                "清理 B 和 C 双方防火墙管理日志",
            ],
            "persistence_result": {"methods": ["隐藏管理账号", "SNMP 后门"]},
            "log_clean_result": {"cleaned": ["深信服管理日志", "VPN 连接日志"]},
            "blue_team_awareness_delta": 20,
        },
        "cross_target": {
            "summary": "跨目标打击 — 从 B 跳板全面控制丙方 C",
            "findings": [
                "利用 B→C VPN 通道，扫描 C 内网发现 12 台存活主机",
                "识别 C 的核心资产: ERP 系统(192.168.50.10)、MES 系统(192.168.50.20)",
                "在 B 上制造大量 SNMP 扫描噪音作为诱饵，实际主攻 C 的 ERP 数据库",
                "从 C 的 ERP 数据库导出全部生产数据和客户信息",
            ],
            "cross_result": {"cross_routes": 2, "via": "b-tech.com.cn"},
            "evasion_result": {"decoy": "B 上 SNMP 扫描噪音", "exfil_path": "HTTPS 混入正常运维流量"},
            "via_target": "b-tech.com.cn",
            "next_hop_targets": ["c-manufacturing.com"],
            "blue_team_awareness_delta": 15,
        },
        "report": {
            "summary": "B 向量 — 供应链跳板攻击链报告已生成",
            "findings": [
                "攻击链: 已控 B(IT外包商) → VPN配置窃取 → C(制造企业) → ERP/MES 系统沦陷",
                "蓝队感知度: 55/100，攻击伪装为正常运维流量",
                "关键脆弱性: 供应商 VPN 无独立ACL、配置文件明文存储、无异常流量监控",
            ],
            "report_result": {
                "critical_findings": [
                    "[!] 乙方运维终端明文存储了丙方的 VPN 配置和预共享密钥",
                    "[!] B→C VPN 专线未限制具体运维端口，可全内网可达",
                    "[!] C 防火墙管理口使用默认运维口令，与 B 共用同一账号",
                    "[!] C 的 ERP/MES 系统无访问审计，数据被批量导出未被发现",
                ],
                "hardening_recommendations": [
                    "取消供应商与客户之间的 VPN 全互通，改为按需审批+按次授权",
                    "为每个接入单位使用独立的 VPN 账号和精细 ACL 策略",
                    "VPN 配置文件加密存储，禁止明文保存预共享密钥",
                    "对 ERP/MES 等核心系统实施数据库访问审计和异常行为告警",
                ],
            },
            "blue_team_awareness_delta": 0,
        },
    },

    # ═══ C — 社工钓鱼 ═══
    "phishing": {
        "social_eng": {
            "summary": "社工钓鱼策划 — 冒充校长/领导生成中文钓鱼邮件",
            "findings": [
                "目标: C 职业学院 (c-vocational.edu.cn)，校长为王校长",
                "生成冒充王校长的紧急安全检查通知（OA 登录链接）",
                "生成冒充财务处的工资明细钓鱼邮件（含宏 Excel 附件）",
                "邮件话术贴合中国教育单位公文风格，预计 45%+ 点击率",
            ],
            "phishing_result": {
                "emails": [
                    {
                        "scenario": "冒充校长紧急通知",
                        "sender": "王校长 <wang@c-vocational.edu.cn>",
                        "subject": "【紧急】关于落实上级安全检查工作的紧急通知",
                    },
                    {
                        "scenario": "冒充财务处工资通知",
                        "sender": "财务处 <cwc@c-vocational.edu.cn>",
                        "subject": "【财务】关于本月绩效工资发放的通知",
                    },
                ],
            },
            "conversation_result": {"conversations": 1, "scenario": "冒充教务处通知"},
            "blue_team_awareness_delta": 10,
        },
        "initial_access": {
            "summary": "钓鱼投放成功 — 3 名教职工点击链接，控制目标终端",
            "findings": [
                "钓鱼邮件发送至 C 职业学院全体教职工邮箱",
                "3 名教职工点击钓鱼链接，其中 1 人在伪造 OA 页面提交了账号密码",
                "通过窃取的 OA 凭证登录真实的 C 职业学院 OA 系统",
                "在 OA 系统上传 Webshell，获得 C 内网立足点",
            ],
            "scan_result": {},
            "exploit_result": {
                "entry_points": [
                    {"method": "钓鱼获取 OA 凭证 + Webshell 上传", "difficulty": "中低", "success_probability": "65%"},
                ],
            },
            "blue_team_awareness_delta": 15,
        },
        "persistence": {
            "summary": "持久化控制 — OA Webshell + 学籍数据库后门 + 计划任务",
            "findings": [
                "OA 系统持久化: 写入计划任务每 1 小时向 C2 回调",
                "学籍数据库创建隐藏查询账号 edu_sync，批量导出学生数据",
                "横向至学工系统，获取全部在校生和毕业生个人信息",
                "清理 OA 操作日志、IIS 日志、数据库审计日志",
            ],
            "persistence_result": {"methods": ["OA Webshell", "数据库后门账号", "计划任务回调"]},
            "log_clean_result": {"cleaned": ["IIS 日志", "OA 操作日志", "数据库审计日志"]},
            "blue_team_awareness_delta": 20,
        },
        "report": {
            "summary": "C 向量 — 社工钓鱼攻击链报告已生成",
            "findings": [
                "攻击链: 冒充校长钓鱼邮件 → OA 凭证窃取 → Webshell 上传 → 学生数据库沦陷",
                "蓝队感知度: 45/100，钓鱼邮件未被邮件网关拦截",
                "关键脆弱性: 缺乏反钓鱼网关、OA 无 MFA、学生数据无脱敏访问控制",
            ],
            "report_result": {
                "critical_findings": [
                    "[!] 钓鱼邮件直接送达教职工收件箱，未被任何反钓鱼机制过滤",
                    "[!] 3 名教职工点击链接，1 人提交 OA 账号密码",
                    "[!] OA 系统无 MFA 二次验证，仅凭密码即可登录",
                    "[!] 学籍数据库可批量导出，无行级访问控制和异常行为检测",
                ],
                "hardening_recommendations": [
                    "部署 AI 反钓鱼邮件网关，重点检测冒充领导的钓鱼邮件",
                    "OA 系统强制启用 MFA 双因子认证",
                    "全员安全意识培训 + 钓鱼演练（每季度一次）",
                    "学籍数据库实施最小权限 + 行级访问控制 + 导出审批",
                    "建立异常登录检测: 非工作时间/异地登录自动告警",
                ],
            },
            "blue_team_awareness_delta": 0,
        },
    },
}


# ── Mock Assistant ────────────────────────────────────────

# 用于从 system_prompt 和 user_message 推断 vector/phase
_VECTOR_MARKER_RE = re.compile(r'"vector":\s*"(\w+)"')


class MockAssistant:
    """模拟 LLM 助手，返回预置响应"""

    def __init__(self, system_prompt: str, tools: list[str]) -> None:
        self._system_prompt = system_prompt
        self._tools = tools

    def run_nonstream(self, messages: list[dict]) -> list[dict]:
        # 从 user message 中提取 vector
        vector = "firewall_breach"
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                m = _VECTOR_MARKER_RE.search(content)
                if m:
                    vector = m.group(1)
                    break

        # 从 system_prompt 推断 phase
        phase = self._guess_phase(self._system_prompt)

        response = MOCK_RESPONSES.get(vector, {}).get(
            phase,
            {"summary": f"{phase} 阶段执行完成"},
        )
        return [{"role": "assistant", "content": json.dumps(response, ensure_ascii=False)}]

    @staticmethod
    def _guess_phase(system_prompt: str) -> str:
        # 仅匹配首行（角色描述行），避免正文中的关键词干扰
        first_line = system_prompt.split("\n")[0] if system_prompt else ""
        markers = [
            ("社会工程学", "social_eng"),
            ("情报收集", "recon"),
            ("边界突破", "initial_access"),
            ("持久化控制", "persistence"),
            ("横向移动", "lateral"),
            ("跨目标打击", "cross_target"),
            ("报告生成", "report"),
        ]
        for keyword, phase in markers:
            if keyword in first_line:
                return phase
        return "recon"


def mock_assistant_factory(system_prompt: str, tools: list[str]) -> MockAssistant:
    return MockAssistant(system_prompt, tools)


# ── 运行演示 ─────────────────────────────────────────────

def run_demo() -> None:
    from security_log_analyzer.apt_core import run_apt_simulation
    from security_log_analyzer.report import build_apt_report

    demo_vectors = [
        {
            "id": "target_A",
            "host": "a-university.edu.cn",
            "vector": "firewall_breach",
            "label": "A — 互联网边界突破（防火墙→内网扫描→横向移动）",
        },
        {
            "id": "target_B",
            "host": "b-tech.com.cn",       # 乙方（IT 外包商，先攻下它）
            "cross_host": "c-manufacturing.com",  # 丙方（真正的目标，通过乙方跳板攻击）
            "vector": "supply_chain",
            "label": "B — 供应链跳板（利用已控乙方攻击丙方）",
        },
        {
            "id": "target_C",
            "host": "c-vocational.edu.cn",
            "vector": "phishing",
            "label": "C — 社工钓鱼（大模型生成中文钓鱼邮件控制设备）",
        },
    ]

    all_results: dict[str, Any] = {}

    for i, cfg in enumerate(demo_vectors):
        print(f"\n{'#' * 60}")
        print(f"#  演示 {i + 1}/3: {cfg['label']}")
        print(f"{'#' * 60}")

        sim_target = {"id": cfg["id"], "host": cfg["host"], "vector": cfg["vector"]}
        cross = cfg.get("cross_host", "")
        if cross:
            sim_target["cross_host"] = cross
            sim_target["cross_id"] = cfg["id"] + "_cross"
        result = run_apt_simulation(sim_target, assistant_factory=mock_assistant_factory)
        all_results[cfg["vector"]] = result

        report = build_apt_report(result)
        print("\n" + report)

    # ── 三向量对比总结 ──
    print(f"\n{'#' * 60}")
    print("#  三种 APT 攻击向量对比总结")
    print(f"{'#' * 60}")
    print()
    print("| 攻击向量 | 入口方式 | 核心手段 | 攻击链长度 | 蓝队感知度 |")
    print("|----------|---------|---------|-----------|-----------|")

    for vector, label in [
        ("firewall_breach", "A-边界突破"),
        ("supply_chain", "B-供应链"),
        ("phishing", "C-社工钓鱼"),
    ]:
        result = all_results.get(vector, {})
        state = result.get("state", {})
        awareness = state.get("blue_team_awareness", 0)
        phases = result.get("phase_results", [])
        phase_count = len(phases)

        if vector == "firewall_breach":
            entry = "互联网公网扫描"
            method = "防火墙弱口令+VPN漏洞"
        elif vector == "supply_chain":
            entry = "已控乙方跳板"
            method = "VPN配置窃取+信任滥用"
        else:
            entry = "钓鱼邮件投递"
            method = "冒充校长+OA凭证窃取"

        print(f"| {label} | {entry} | {method} | {phase_count} 阶段 | {awareness}/100 |")

    print()
    print("结论: 三种向量可从不同入口独立攻击同一目标体系，组合使用可形成多维打击面。")


if __name__ == "__main__":
    run_demo()
