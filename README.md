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
| `firewall` | 互联网边界突破 — 端口扫描→服务探测→漏洞利用→初始接入 |
| `supply` | 供应链跳板 — 以目标为跳板攻击下游，实现横向移动 |
| `phishing` | 社工钓鱼 — 邮件/对话场景生成，社工工程学攻击 |

### 目录结构

```
├── security_log_analyzer/   # 核心分析引擎
│   ├── apt_core.py          # APT 仿真核心编排
│   ├── apt_tools.py         # 攻击工具集
│   ├── agent.py             # LLM Agent 封装
│   ├── config.py            # API 配置（自动加载 .env）
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
