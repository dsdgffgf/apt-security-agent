# 安全智能体 — 动手操作指南

## 环境速查

| 项目 | 值 |
|------|-----|
| Python | `C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe` |
| 中文不乱码 | 命令前加 `PYTHONIOENCODING=utf-8` |
| API Key | 已在 `.claude/settings.local.json` 配置，Claude Code 运行时自动注入 |

如果用系统终端（非 Claude Code），先设环境变量：

```powershell
$env:DEEPSEEK_API_KEY = "sk-47248a7911ca4d6da1b10abd4e1babad"
```

---

## 一、防御模式 — 分析安全日志

```bash
# 单个日志文件
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log

# 其他测试日志（18 个可选）
test_logs/web_sql_injection.log      # SQL 注入
test_logs/web_xss.log               # XSS 攻击
test_logs/command_injection.log      # 命令注入
test_logs/directory_traversal.log    # 目录遍历
test_logs/firewall.log              # 防火墙日志
test_logs/normal_ssh.log            # 正常 SSH（对照组）
test_logs/mixed_attack.log          # 混合攻击

# 批量分析整个目录
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/
```

**输出**：结构化中文报告，含风险分（0-100）、攻击类型、行业标准对照、处置建议。

---

## 二、渗透模式 — 扫描目标弱点

```bash
# 在线合法靶场（直接用）
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer testphp.vulnweb.com --mode pentest
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest

# 本地靶机（装了 Metasploitable 后用它的 IP）
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer 192.168.1.100 --mode pentest
```

**输出**：JSON，含 open_ports / services / web_tech / vulnerabilities / risk_level / recommendations。

### 受限地址会自拦截

```
127.0.0.1 → 被拒（回环地址）
0.0.0.0   → 被拒（保留地址）
169.254.x.x → 被拒（链路本地）
```

### 渗透工具链

```
port_scan → service_detect → dir_enum → web_fingerprint → vuln_check → pentest_report
  扫端口      抓服务版本      枚举路径      识别技术栈        CVE匹配       汇总报告
```

---

## 三、攻击模式 — 生成攻击载荷

```bash
# 有目标
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack

# 无目标（通用研究）
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer "" --mode attack
```

**输出**：JSON，含 payloads（SQLi/XSS/CMD）、bypass_variants（6 种编码）、kill_chain（5 阶段攻击路径）。

---

## 四、本地靶场搭建

### 最简方案 — Docker（推荐）

```bash
docker run -d -p 80:80 vulnerables/web-dvwa
docker run -d -p 8080:80 bkimminich/juice-shop
```

然后：
```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer localhost --mode pentest
```

### 无 Docker — VirtualBox + Metasploitable 2

1. 装 VirtualBox：https://www.virtualbox.org/wiki/Downloads
2. 下 Metasploitable 2：https://sourceforge.net/projects/metasploitable
3. 导入虚拟机 → 网络设桥接 → 启动 → `ifconfig` 看 IP
4. 用工具打：`"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer <虚拟机IP> --mode pentest`

---

## 常见问题

| 问题 | 解决 |
|------|------|
| 中文乱码 | 命令前加 `PYTHONIOENCODING=utf-8` |
| `qwen-agent not installed` | 必须用 conda 环境的 Python 路径，不要用系统默认的 python |
| 渗透扫不出结果 | 网络延迟导致超时，换个目标或等网络好了再试 |
| 想改超时 | 编辑 `pentest_tools.py` 里 `sock.settimeout(2.0)` 改大 |
| 想加端口 | 编辑 `pentest_tools.py` 里 `COMMON_PORTS` 列表 |
