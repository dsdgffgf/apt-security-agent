# 安全日志智能分析系统 - 运行指南

## 环境要求

- **Python 环境**：必须使用 `security-log-analyzer` conda 环境
- **Python 路径**：`C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe`
- **API Key**：已在 `.claude/settings.local.json` 中配置 `DEEPSEEK_API_KEY`，通过 Claude Code 运行时自动注入

如果用外部终端（不用 Claude Code），需手动设置环境变量：

```powershell
# PowerShell
$env:DEEPSEEK_API_KEY = "sk-47248a7911ca4d6da1b10abd4e1babad"
```

```cmd
# CMD
set DEEPSEEK_API_KEY=sk-47248a7911ca4d6da1b10abd4e1babad
```

**Windows 中文输出注意**：如果遇到终端输出乱码，在命令前加 `PYTHONIOENCODING=utf-8`：

```bash
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer ...
```

## 启动命令

以下命令均在项目根目录下执行：

```
d:\Users\nyh\Downloads\Users\nyh\Desktop\新建文件夹 (5)\w\w
```

### 三种运行模式

| 模式 | `--mode` | 说明 |
|------|----------|------|
| **defense**（默认）| `defense` | 日志安全分析，检测攻击迹象 |
| **pentest** | `pentest` | 渗透测试：端口扫描、服务检测、漏洞匹配 |
| **attack** | `attack` | 攻击模拟研究：payload 生成、绕过测试、Kill Chain 规划 |

---

### 1. 防御模式（日志安全分析）

分析日志文件，检测暴力破解、SQL 注入、XSS 等攻击：

```bash
# 单个文件（默认使用 DeepSeek 智能体）
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log

# 等同于
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log --mode defense

# 启用对比模式（本地 + AI 并排对比）
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log --compare

# 批量分析整个目录
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/
```

### 2. 渗透测试模式

对目标 IP/域名进行受控安全测试（需授权）：

```bash
# 扫描外部目标（需获得授权）
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest

# 被拒绝的目标（内网受保护地址段自动拦截）
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer 127.0.0.1 --mode pentest
# → 输出：渗透测试失败: 目标校验失败: 目标 127.0.0.1 属于受限地址段 127.0.0.0/8，已拒绝
```

渗透测试工具链：port_scan → service_detect → dir_enum → web_fingerprint → vuln_check → pentest_report

### 3. 攻击模拟模式

用于红蓝对抗和安全研究，生成 payload、绕过测试、Kill Chain 规划：

```bash
# 针对特定目标
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack

# 无特定目标（生成通用攻击研究内容）
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer "" --mode attack
```

攻击模拟工具链：info_gather → payload_gen → bypass_test → attack_plan

---

## 测试日志列表（防御模式）

`test_logs/` 目录下有 18 个测试日志：

| 文件名 | 场景 |
|--------|------|
| `ssh_bruteforce.log` | SSH 暴力破解 |
| `ssh_success_after_failures.log` | 多次失败后成功登录 |
| `web_sql_injection.log` | Web SQL 注入 |
| `web_xss.log` | XSS 跨站脚本 |
| `web_scanning.log` | Web 扫描探测 |
| `command_injection.log` | 命令注入 |
| `directory_traversal.log` | 目录遍历 |
| `sensitive_file_access.log` | 敏感文件访问 |
| `account_enumeration.log` | 账号枚举 |
| `off_hours_access.log` | 非工作时间访问 |
| `firewall.log` | 防火墙日志 |
| `waf_alert.log` | WAF 告警 |
| `api_anomaly.log` | API 异常 |
| `cloud_login.log` | 云平台登录 |
| `iot_device_anomaly.log` | IoT 设备异常 |
| `normal_ssh.log` | 正常 SSH（对照组） |
| `normal_web_access.log` | 正常 Web 访问（对照组） |
| `mixed_attack.log` | 混合攻击 |

## 输出说明

### 防御模式输出

分析结果是一份结构化的中文报告，包含五个部分：

1. **基本信息** -- 日志来源、类型、分析范围、是否使用 AI
2. **风险摘要** -- Python 风险分、AI 最终风险分、是否攻击、攻击类型、置信度、行业标准对照
3. **关键证据** -- 高频账号、失败登录次数、具体攻击日志行
4. **行业标准依据** -- OWASP、MITRE ATT&CK、CWE、NIST CSF 对照
5. **处置建议** -- 针对性的安全建议

### 渗透模式输出

JSON 格式，包含：target、open_ports_summary、services_detected、web_tech、discovered_dirs、vulnerabilities、risk_level、recommendations、summary

### 攻击模式输出

JSON 格式，包含：target_info、payloads、bypass_variants、kill_chain、risk_note、summary

## 注意事项

1. **必须用 conda 环境**：系统默认 Python 缺少 `qwen-agent` 依赖
2. **API Key 不外泄**：`DEEPSEEK_API_KEY` 不要提交到 git
3. **渗透/攻击模式需授权**：仅对已获书面授权的目标使用，内网受保护地址段（127.0.0.0/8、0.0.0.0/8、169.254.0.0/16 等）自动拦截
4. **API 有网络延迟**：所有模式默认调用 DeepSeek API，需网络通畅
5. **日志编码**：工具默认用 UTF-8 读取日志文件
6. **Windows 编码**：中文输出乱码时加 `PYTHONIOENCODING=utf-8` 前缀
