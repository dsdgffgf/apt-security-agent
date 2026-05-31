# Step 4: Add UA-based content fetching using discovered codenames
filepath = "d:\\Users\\nyh\\Downloads\\Users\\nyh\\Desktop\\新建文件夹 (5)\\w\\w\\security_log_analyzer\\apt_core.py"

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

old = '''        # ── 哈希提取 + 破解（从 SMB 文件和页面内容中） ──
        _found_by_hash = False
        safe_print("  [hash_extract] 从 SMB 文件和页面内容提取哈希...")'''

new = '''        # ── 用已发现的代号作为 UA 抓受保护页面（UA 认证目标专用） ──
        _codename_pages = _auto_fetch_protected_pages(target, port, recon_details)
        if _codename_pages:
            safe_print(f"  [ua-fetch] 用代号抓取 {len(_codename_pages)} 个受保护页面")
            results["http_attacks"].update(_codename_pages)

        # ── 哈希提取 + 破解（从 SMB 文件和页面内容中） ──
        _found_by_hash = False
        safe_print("  [hash_extract] 从 SMB 文件和页面内容提取哈希...")'''

if old not in content:
    print("Pattern not found!")
else:
    content = content.replace(old, new, 1)
    # Also add the _auto_fetch_protected_pages function near _auto_fetch_interesting_pages
    # Find the _auto_fetch_interesting_pages function
    old_fn = '''def _auto_fetch_interesting_pages(target: str, recon_details: dict[str, Any]) -> dict[str, Any]:
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
                        "target": target, "port": _port, "path": _path,
                    })
                    results[f"page_{_port}_{_path.replace('/', '_')}"] = _content
                except Exception:
                    pass
    return results'''

    new_fn = '''def _auto_fetch_interesting_pages(target: str, recon_details: dict[str, Any]) -> dict[str, Any]:
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
                        "target": target, "port": _port, "path": _path,
                    })
                    results[f"page_{_port}_{_path.replace('/', '_')}"] = _content
                except Exception:
                    pass
    return results


def _auto_fetch_protected_pages(target: str, port: int, recon_details: dict[str, Any]) -> dict[str, Any]:
    """用 RECON 发现的 codename/UA 批量抓取受保护页面"""
    import re as _re
    results: dict[str, Any] = {}

    # Collect all discovered codenames/UA values from recon
    codenames: set[str] = set()
    http_results = recon_details.get("http_results", {})
    for _k, _r in http_results.items():
        if isinstance(_r, dict):
            for field in ("valid_codenames", "anomalies", "results"):
                items = _r.get(field, [])
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            codenames.add(item.strip())
                        elif isinstance(item, dict):
                            for subk in ("agent", "codename", "username", "ua_value", "value"):
                                v = item.get(subk, "")
                                if isinstance(v, str) and v.strip():
                                    codenames.add(v.strip())

    if not codenames:
        return results

    safe_print(f"  [ua-fetch] 用 {len(codenames)} 个代号抓取受保护页面: {sorted(codenames)[:10]}...")

    # Endpoints that might have protected content
    endpoints = ["/", "/admin", "/flag", "/dashboard", "/secret", "/config", "/status", "/users", "/credentials", "/backup"]
    for ua in codenames:
        for path in endpoints:
            try:
                _resp = run_local_tool("web_content_fetch", {
                    "target": target, "port": port, "path": path,
                    "user_agent": ua,
                })
                if isinstance(_resp, dict):
                    body = _resp.get("body") or _resp.get("content") or _resp.get("body_preview", "")
                    if isinstance(body, str) and len(body) > 50 and "unauthorized" not in body.lower() and "access denied" not in body.lower():
                        results[f"ua_{ua}_{path.replace('/', '_')}"] = _resp
            except Exception:
                pass

    safe_print(f"  [ua-fetch] 获取 {len(results)} 个非空页面")
    return results'''


    content = content.replace(old_fn, new_fn, 1)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print("done - added ua-fetch step + _auto_fetch_protected_pages()")
