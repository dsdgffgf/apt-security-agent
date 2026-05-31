# 攻防渗透一体 安全智能体 — 功能与测试报告

## 项目概述

基于 **Qwen-Agent 框架 + DeepSeek 大模型 API** 构建的安全智能体，支持三种运行模式：

| 模式 | 定位 | 核心能力 |
|------|------|----------|
| **defense** | 日志安全分析 | 解析安全日志，检测暴力破解/SQL注入/XSS/命令注入等攻击 |
| **pentest** | 渗透测试 | 端口扫描、服务识别、目录枚举、Web指纹、CVE漏洞匹配 |
| **attack** | 攻击模拟研究 | payload生成、WAF绕过测试、OSINT信息收集、Kill Chain规划 |

---

## 架构分层

```
┌─────────────────────────────────────────┐
│  CLI 入口 (__main__.py)                  │
│  --mode defense | pentest | attack       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  智能体编排层 (agentic.py)               │
│  系统提示词 + Assistant.run_nonstream    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  Qwen-Agent 注册层 (qwen_assistant.py)   │
│  按模式注册不同工具集 + 参数schema        │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  Python 工具层 (tools.py + pentest_tools.py) │
│  16 个本地工具函数                       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  DeepSeek API (deepseek.py)             │
│  大模型推理、综合研判、策略生成           │
└─────────────────────────────────────────┘
```

**分工原则**：Python 工具做数据解析和规则初筛，DeepSeek 大模型做最终判断和策略推理。

---

## 工具清单（16 个）

### 防御工具（6 个）

| 工具 | 功能 |
|------|------|
| `read_log_file` | 读取日志文件 |
| `parse_log` | 解析日志为结构化数据 |
| `summarize_log` | 统计总数/时间范围/IP/账号 |
| `extract_basic_patterns` | 提取异常模式（暴力破解、注入等） |
| `risk_hint` | 规则引擎风险评分 |
| `format_evidence` | 整理并脱敏关键证据 |

### 渗透工具（6 个）

| 工具 | 功能 |
|------|------|
| `port_scan` | TCP 端口扫描（24 常用端口） |
| `service_detect` | 抓取 Banner 识别服务版本 |
| `dir_enum` | Web 目录枚举（18 常见路径） |
| `web_fingerprint` | HTTP 响应头技术栈识别 |
| `vuln_check` | CVE 规则库匹配（9 条规则） |
| `pentest_report` | 汇总发现，生成结构化报告 |

### 攻击工具（4 个）

| 工具 | 功能 |
|------|------|
| `payload_gen` | SQLi/XSS/CMD 测试载荷生成 |
| `bypass_test` | 6 种编码绕过变体生成 |
| `info_gather` | DNS 解析/反向解析 |
| `attack_plan` | Kill Chain 攻击路径规划 |

---

## 安全约束

- **目标校验**：自动拦截 127.0.0.0/8、0.0.0.0/8、169.254.0.0/16、224.0.0.0/4、240.0.0.0/4
- **启动警告**：pentest/attack 模式启动时打印授权警告
- **不持久化**：渗透工具只探测不植入

---

## 测试结果

### 环境

- Python：`C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe`（qwen-agent 0.0.34）
- 模型：DeepSeek Chat API
- 系统：Windows 11

---

### 1. 防御模式测试

**命令**：
```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log --mode defense
```

**结果**：通过

**输出摘要**：

```
日志来源：test_logs\ssh_bruteforce.log
日志类型：SSH 登录日志
分析范围：2026-05-14 03:12:01 至 2026-05-14 03:13:01

Python 风险：71/100（高危）
最终风险：90/100（严重）
是否异常：是
疑似攻击：是
主要攻击类型：暴力破解尝试、高频请求、失败登录聚集
攻击成功判断：攻击未成功（日志中无成功登录记录，16 次尝试均失败）
置信度：高置信度

行业标准对照：
  OWASP A07 Identification and Authentication Failures
  MITRE ATT&CK T1110 Brute Force
  CWE-307 Improper Restriction of Excessive Authentication Attempts
  MITRE ATT&CK T1595 Active Scanning
  NIST CSF DE.CM-7

关键证据：
  - 高风险账号：root(15)
  - 失败事件数：16
  - 同一 IP 203.0.113.50 对 root 账号大量失败登录

处置建议：
  - 加固系统管理员账号登录策略
  - 修改管理员账号密码并核查越权账号
  - 临时封禁攻击 IP
  - 检查系统是否存在异常进程/文件
```

---

### 2. 渗透测试模式 — 目标校验

**命令**：
```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer 127.0.0.1 --mode pentest
```

**结果**：通过（正确拦截）

```
渗透测试失败: 目标校验失败: 目标 127.0.0.1 属于受限地址段 127.0.0.0/8，已拒绝
```

---

### 3. 渗透测试模式 — 外部目标

**命令**：
```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest
```

**结果**：通过

**输出摘要**：

```json
{
  "target": "scanme.nmap.org",
  "open_ports_summary": {
    "total": 2,
    "ports": [22, 80]
  },
  "services_detected": [
    {"port": 22, "service": "OpenSSH", "version": "6.6.1p1 Ubuntu-2ubuntu2.13"},
    {"port": 80, "service": "Apache", "version": "2.4.7 (Ubuntu)"}
  ],
  "web_tech": ["Apache"],
  "discovered_dirs": [
    {"path": "/", "status": 200}
  ],
  "vulnerabilities": [
    {"cve": "CVE-2021-41773", "severity": "critical", "service": "Apache"},
    {"cve": "CVE-2021-42013", "severity": "critical", "service": "Apache"}
  ],
  "risk_level": "高危",
  "recommendations": [
    "立即升级 Apache HTTP Server 到 2.4.51 或更高版本",
    "SSH 端口对外开放，建议限制来源 IP 或改用密钥认证",
    "定期更新系统软件包"
  ],
  "summary": "目标开放 2 个端口（22/SSH、80/HTTP），Apache 2.4.7 存在 2 个严重级别 CVE 漏洞，整体风险等级为高危。"
}
```

**渗透测试工作流**：
1. port_scan → 发现 22/SSH, 80/HTTP 开放
2. service_detect → 识别 OpenSSH 6.6.1p1, Apache 2.4.7
3. dir_enum → 枚举到根路径 `/`（状态 200）
4. web_fingerprint → 识别 Apache 技术栈
5. vuln_check → 匹配 CVE-2021-41773（路径遍历）、CVE-2021-42013（RCE）
6. pentest_report → 汇总为高危，给出升级建议

---

### 4. 攻击模拟模式

**命令**：
```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack
```

**结果**：通过

**输出摘要**：

```json
{
  "selected_tools": ["info_gather", "payload_gen", "bypass_test", "attack_plan"],
  "target_info": {
    "ip": "172.66.147.243",
    "hostname": "example.com"
  },
  "payloads": [
    {"type": "sqli", "payload": "' OR '1'='1", "encoding": "plain"},
    {"type": "sqli", "payload": "' UNION SELECT NULL--", "encoding": "plain"},
    {"type": "xss", "payload": "<script>alert(1)</script>", "encoding": "plain"},
    {"type": "xss", "payload": "<img src=x onerror=alert(1)>", "encoding": "plain"},
    {"type": "cmd", "payload": "; ls -la", "encoding": "plain"},
    {"type": "cmd", "payload": "| whoami", "encoding": "plain"}
  ],
  "bypass_variants": {
    "original": "' OR '1'='1",
    "variants": {
      "url": "%27%20%4F%52%20%27%31%27%3D%27%31",
      "double_url": "%2527%2520%254F%2552%2520%2527%2531%2527%253D%2527%2531",
      "unicode": "\\u0027\\u0020\\u004F\\u0052\\u0020\\u0027\\u0031...",
      "hex": "0x27204f52202731273d2731",
      "base64": "JyBPUiAnMSc9JzE=",
      "case_mix": "' Or '1'='1"
    }
  },
  "kill_chain": [
    {"phase": "reconnaissance", "tools": ["info_gather", "port_scan"]},
    {"phase": "weaponization", "tools": ["payload_gen"]},
    {"phase": "delivery", "tools": ["dir_enum", "web_fingerprint"]},
    {"phase": "exploitation", "tools": ["vuln_check", "bypass_test"]},
    {"phase": "reporting", "tools": ["pentest_report"]}
  ],
  "summary": "完成了信息收集、SQL注入/XSS/命令注入三类payload生成、6种编码绕过变体测试、完整5阶段Kill Chain攻击路径规划。"
}
```

**攻击模拟工作流**：
1. info_gather → 解析目标 example.com 得 IP 172.66.147.243
2. payload_gen → 生成 SQLi/XSS/CMD 各 2 条共 6 条载荷
3. bypass_test → 对 `' OR '1'='1` 生成 6 种编码变体
4. attack_plan → 构建 reconnaissance → weaponization → delivery → exploitation → reporting 完整 Kill Chain

---

## 测试总结

| 测试项 | 状态 | 备注 |
|--------|------|------|
| defense 模式 — 单个日志文件 | **通过** | SSH 暴力破解检测正确，评分 90/100 严重 |
| defense 模式 — 批量目录分析 | **通过** | 遍历 .log 文件逐一分析 |
| defense 模式 — 对比模式 | **通过** | 本地+AI 并排对比，显示分差 |
| pentest 模式 — 受限目标拦截 | **通过** | 127.0.0.1 正确拒绝 |
| pentest 模式 — 外部端口扫描 | **通过** | 发现 22/80 端口 |
| pentest 模式 — 服务版本检测 | **通过** | 识别 OpenSSH/Apache 及版本 |
| pentest 模式 — 目录枚举 | **通过** | 枚举 18 常见路径 |
| pentest 模式 — Web 指纹 | **通过** | 识别 Apache 技术栈 |
| pentest 模式 — CVE 匹配 | **通过** | 匹配 2 个严重 CVE |
| pentest 模式 — 报告生成 | **通过** | 结构化 JSON + 修复建议 |
| attack 模式 — 信息收集 | **通过** | DNS 解析正常 |
| attack 模式 — Payload 生成 | **通过** | 三类 6 条载荷 |
| attack 模式 — 绕过测试 | **通过** | 6 种编码变体 |
| attack 模式 — Kill Chain | **通过** | 5 阶段路径规划 |
| 安全约束 — 地址校验 | **通过** | 5 个受限段全部拦截 |

**测试结论**：三种模式、16 个工具、完整工具链全部正常运行，安全约束有效。
