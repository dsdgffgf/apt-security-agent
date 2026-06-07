# APT 攻击模拟管理系统

基于大模型（DeepSeek）的 APT 攻击模拟与安全分析平台，支持 CLI 命令行和 Web Dashboard 两种运行方式。

## 环境要求

- Python >= 3.10
- Git

## 部署步骤

### 1. 克隆仓库

```bash
git clone https://github.com/dsdgffgf/apt-security-agent.git
cd apt-security-agent
```

### 2. 创建虚拟环境

```bash
# 方式 A：conda
conda create -n security-log-analyzer python=3.13
conda activate security-log-analyzer

# 方式 B：venv
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置 API Key

```bash
# 复制模板文件
cp .env.example .env
```

编辑 `.env` 文件，填入你的 DeepSeek API Key：

```
DEEPSEEK_API_KEY=sk-你的真实密钥
```

> 注册地址：https://platform.deepseek.com

### 5. 运行

#### CLI 命令行模式

```bash
# APT 攻击模拟（互联网边界突破）
python -m security_log_analyzer 192.168.1.1 --mode apt --vector firewall

# APT 攻击模拟（供应链跳板）
python -m security_log_analyzer 192.168.1.1 --mode apt --vector supply

# APT 攻击模拟（社工钓鱼）
python -m security_log_analyzer example.com --mode apt --vector phishing

# 渗透测试
python -m security_log_analyzer 192.168.1.1 --mode pentest

# 日志安全分析
python -m security_log_analyzer /var/log/auth.log --mode defense
```

#### Web Dashboard

```bash
python web_dashboard/app.py
```

浏览器打开 `http://127.0.0.1:5000`，在界面中选择目标和攻击向量，切换 Mock/Real 模式后点击启动。

### 三种攻击向量

| 向量 | 说明 |
|------|------|
| `firewall` | **互联网边界突破** — 动态攻击方案生成 → 工具缓存复用 → 漏洞利用 → 初始接入 |
| `supply` | **供应链跳板** — 6种横向移动技术（PsExec/WMI/计划任务/哈希传递/SSH密钥复用/端口转发） → 自动降级 → 内网资产发现 |
| `phishing` | **社工钓鱼闭环** — 钓鱼邮件 + VBA宏附件生成 + C2 回传监听 → 完整控制设备模拟 |

#### 模式A：互联网边界突破（firewall）改进

1. **动态攻击方案生成**：不再使用硬编码攻击流程。智能体先分析 RECON 阶段收集的目标特征（端口、服务版本、Web认证机制、CVE），自动输出最优攻击方案。
2. **工具缓存复用**：基于 `工具名 + 目标特征hash` 生成唯一签名，相同签名的工具调用直接返回缓存结果，避免重复 LLM 生成，节省 token。

#### 模式B：供应链跳板（supply）改进

1. **6种横向移动技术**：`apt_psexec` / `apt_wmi_exec` / `apt_schtasks` / `apt_pass_the_hash` / `apt_ssh_key_reuse` / `apt_port_forward`
2. **自动降级策略**：PsExec 失败 → 尝试 WMI → 失败 → 尝试计划任务 → 失败 → 尝试 SSH 密钥复用。每种失败原因记录到 `state.notes`。
3. **内网资产发现**：通过 `apt_internal_scan` 从跳板扫描内网存活主机（支持 nmap SSH 远程执行 / Python socket 本地回退）。

#### 模式C：社工钓鱼（phishing）改进

1. **VBA 宏附件生成**：`generate_macro_doc()` 生成 .xlsm/.docm 文件，内含 VBA 宏代码。宏功能（无害）：获取主机名、用户名、内网IP，通过 HTTP POST 回传 C2 服务器。
2. **C2 监听器**：`security_log_analyzer/c2_listener.py` — `GET /payload.ps1` 返回测试脚本，`POST /capture` 接收回调信息，`GET /` 显示实时状态页面。
3. **完整闭环**：SOCIAL_ENG 阶段自动生成钓鱼邮件 + 宏附件 → C2 URL 注入 → 等待宏执行回传。

#### 启动 C2 监听器

```bash
python -m security_log_analyzer.c2_listener --host 0.0.0.0 --port 8080
```



### 目录结构

```
├── security_log_analyzer/   # 核心分析引擎
│   ├── apt_core.py          # APT 仿真核心编排（含 plan_attack 动态方案 + 多技术横向移动）
│   ├── apt_tools.py         # 攻击工具集（含 TOOL_CACHE 缓存 + 宏生成 + 6种横向移动）
│   ├── c2_listener.py       # C2 回传监听器（社工钓鱼）
│   ├── agent.py             # LLM Agent 封装
│   ├── config.py            # API 配置（含 C2_HOST/C2_PORT）
│   └── __main__.py          # CLI 入口
├── web_dashboard/           # Web 管理面板
│   ├── app.py               # Flask 后端
│   └── templates/           # 前端页面
├── requirements.txt         # Python 依赖
├── .env.example             # API Key 模板
└── README.md
```

### 常见问题

**Q: 运行报错 "DEEPSEEK_API_KEY is not configured"**

确保已执行 `cp .env.example .env` 并在 `.env` 中填入了真实密钥。

**Q: Web Dashboard 启动后无法访问**

默认监听 `127.0.0.1:5000`，请确认端口未被占用。如需外网访问，编辑 `web_dashboard/app.py` 最后一行的 `host` 参数。

**Q: 真实模式耗时多久？**

取决于目标主机情况，通常 2-5 分钟。Mock 模式约 2 秒，仅用于界面调试。
