# 安全智能体 — 演示指南

## 演示方式选择

| 方式 | 适合场景 | 准备时间 |
|------|----------|----------|
| **直接终端演示** | 现场演示、会议 | 0 分钟 |
| **录屏** | 分享视频、发群 | 10 分钟 |
| **导出报告截图** | PPT、文档 | 5 分钟 |

---

## 方式一：终端现场演示（推荐）

按顺序在终端执行以下命令，每步之间有自然的讲解时间。

### 第一幕：防御 — 日志分析（约 30 秒）

```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log
```

**演示要点**：指着输出说

> "这是防御模式。输入是一份 SSH 日志文件，Python 工具先做解析——统计出 16 条失败登录、同一 IP 对 root 账号的暴力破解——然后 DeepSeek 大模型综合研判，输出风险评分 90/100 严重，同时对照了 OWASP、MITRE ATT&CK、NIST 等行业标准，给出处置建议。全程不需要我写任何规则。"

### 第二幕：渗透 — 端口扫描+漏洞发现（约 60 秒）

```bash
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest
```

**演示要点**：

> "现在切换到渗透模式。目标是一个公开测试服务器。智能体会自动走完整个渗透链——先用 50 线程并发扫描 100+ 端口，找到 5 个开放端口；然后对每个端口抓取服务 Banner，识别出 OpenSSH 6.6.1p1 和 Apache 2.4.7；接着枚举 18 个 Web 路径、检查 6 项 HTTP 安全头、检测表单 CSRF 保护、探测参数注入——最终自动生成这份结构化报告，详细列出了漏洞、风险等级和修复建议。"

### 第三幕：攻击 — Payload 生成（约 30 秒）

```bash
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack
```

**演示要点**：

> "攻击模式用于安全研究。我们对目标完成信息收集、生成了 SQL 注入/XSS/命令注入三类测试载荷，每种载荷都有 6 种编码绕过变体，最后构建了完整 5 阶段 Kill Chain 攻击路径。所有操作都是字符串级别的研究模拟，不做实际攻击。"

### 第四幕：安全约束演示（10 秒）

```bash
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer 127.0.0.1 --mode pentest
```

> "如果有人想扫自己的机器或内网地址，系统会自动拦截。127.0.0.1、0.0.0.0、169.254.x.x 等 5 个受限地址段全部拒绝。"

---

## 方式二：录屏

用 Windows 自带录屏（Win+Alt+R）或 OBS：

1. 打开终端，设好 `PYTHONIOENCODING=utf-8`
2. 按方式一的顺序依次执行命令
3. 每个命令执行完暂停几秒，让观众看清输出
4. 总共约 3-4 分钟

也可以用 `script` 命令录制终端会话（输出为文本）：

```bash
# 开始录制
script demo.log

# 执行三个命令
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack

# 结束录制
exit
```

---

## 方式三：导出静态报告

把三个模式的输出保存为文本文件，放进 PPT 或文档：

```bash
# 导出防御报告
"C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer test_logs/ssh_bruteforce.log > demo_defense.txt 2>&1

# 导出渗透报告
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer scanme.nmap.org --mode pentest > demo_pentest.json 2>&1

# 导出攻击报告
PYTHONIOENCODING=utf-8 "C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe" -m security_log_analyzer example.com --mode attack > demo_attack.json 2>&1
```

---

## 演示前检查清单

- [ ] 终端支持 UTF-8 显示（命令前加 `PYTHONIOENCODING=utf-8`）
- [ ] 网络通畅（需要访问 DeepSeek API 和目标服务器）
- [ ] Conda 环境正确：`C:/Users/nyh/.conda/envs/security-log-analyzer/python.exe`
- [ ] 提前跑过一次，知道大概耗时（防御 10s、渗透 60s、攻击 40s）
- [ ] 准备好解说词（见每幕的"演示要点"）

---

## 一句话电梯演讲

> "这是一个基于大模型驱动的攻防一体安全智能体。**防御**端，给它一份日志，它自动分析攻击行为并输出对标国际标准的报告；**渗透**端，给它一个目标，它自动完成端口扫描、服务识别、漏洞匹配、Web 安全检测全套流程；**攻击**端，它能生成测试载荷和 Kill Chain 攻击路径。底层 19 个 Python 工具做数据采集，DeepSeek 大模型做智能编排和研判。三种模式共用一个框架，切模式只需改一个参数。"
