"""APT 攻击模拟改进功能单元测试

覆盖:
  1. 工具缓存复用 (signature + cache)
  2. 动态攻击方案生成 (plan_attack)
  3. 多技术横向移动 (PsExec/WMI/Schtasks/PtH/SSH-key-reuse/内网扫描)
  4. 宏文档生成 (generate_macro_doc)
  5. C2 监听器 (c2_listener)
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from security_log_analyzer.apt_tools import (
    TOOL_CACHE,
    apt_internal_scan,
    apt_pass_the_hash,
    apt_psexec,
    apt_schtasks,
    apt_ssh_key_reuse,
    apt_wmi_exec,
    generate_macro_doc,
    lookup_tool_cache,
    store_tool_cache,
    tool_signature,
)
from security_log_analyzer.c2_listener import clear_captured_hosts, get_local_ip
from security_log_analyzer.config import C2_HOST, C2_PORT, C2_ENABLED
from security_log_analyzer.models import (
    AptPhase,
    AptSimulationState,
    AptTarget,
    AttackPlan,
    PhishingCallback,
    PlanStep,
    ToolCacheEntry,
)


# ── 1. 工具缓存复用 ──────────────────────────────────────

class TestToolCache(unittest.TestCase):
    """测试工具签名生成和缓存复用"""

    def test_signature_deterministic(self):
        """相同参数生成相同签名"""
        sig1 = tool_signature("ssh_brute", "10.0.0.1", "ssh", "OpenSSH-7.4", "CVE-2024-6387")
        sig2 = tool_signature("ssh_brute", "10.0.0.1", "ssh", "OpenSSH-7.4", "CVE-2024-6387")
        self.assertEqual(sig1, sig2)

    def test_signature_different(self):
        """不同参数生成不同签名"""
        sig1 = tool_signature("ssh_brute", "10.0.0.1", "ssh")
        sig2 = tool_signature("http_exploit", "10.0.0.1", "http")
        self.assertNotEqual(sig1, sig2)

    def test_store_and_lookup(self):
        """存储后能查到，且 hit_count 递增"""
        sig = tool_signature("test_tool", "target1", "service1")
        store_tool_cache(sig, "print('hello')", {"param": "value"})
        entry = lookup_tool_cache(sig)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["tool_code"], "print('hello')")
        self.assertEqual(entry["tool_params"], {"param": "value"})
        self.assertEqual(entry["hit_count"], 1)
        # 第二次命中 hit_count 递增
        lookup_tool_cache(sig)
        self.assertEqual(entry["hit_count"], 2)

    def test_lookup_miss(self):
        """未存储的签名返回 None"""
        result = lookup_tool_cache("nonexistent_signature")
        self.assertIsNone(result)

    def test_cache_is_global(self):
        """TOOL_CACHE 是模块级全局字典"""
        self.assertIsInstance(TOOL_CACHE, dict)
        sig = tool_signature("global_test", "1.2.3.4")
        store_tool_cache(sig, "code", {})
        self.assertIn(sig, TOOL_CACHE)


# ── 2. 动态攻击方案生成 ──────────────────────────────────

class TestAttackPlan(unittest.TestCase):
    """测试 plan_attack 动态方案生成"""

    def test_plan_basic(self):
        """基本方案生成 — HTTP + SSH 端口（直接使用 fallback）"""
        from security_log_analyzer.apt_core import _plan_attack_fallback

        features = {
            "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 22, "service": "ssh"},
                {"port": 445, "service": "microsoft-ds"},
            ],
            "categories": {"http": [80], "ssh": [22], "smb": [445]},
            "cve_findings": [],
        }

        plan = _plan_attack_fallback("10.0.0.1", features)
        self.assertIn("plan_id", plan)
        self.assertIn("phases", plan)
        steps = plan["phases"].get("initial_access", [])
        self.assertGreater(len(steps), 0)
        tool_names = [s["tool"] for s in steps]
        self.assertIn("web_content_fetch", tool_names)
        self.assertIn("apt_smb_enum", tool_names)

    def test_plan_empty_ports(self):
        """无开放端口时的方案"""
        from security_log_analyzer.apt_core import _plan_attack_fallback

        features = {"open_ports": [], "categories": {}}
        plan = _plan_attack_fallback("10.0.0.1", features)
        self.assertIn("rationale", plan)

    def test_plan_with_cve(self):
        """有 CVE 时包含验证步骤"""
        from security_log_analyzer.apt_core import _plan_attack_fallback

        features = {
            "open_ports": [{"port": 80, "service": "http"}],
            "categories": {"http": [80]},
            "cve_findings": [{"cve_id": "CVE-2021-41773"}],
        }

        plan = _plan_attack_fallback("10.0.0.1", features)
        steps = plan["phases"].get("initial_access", [])
        tool_names = [s["tool"] for s in steps]
        self.assertIn("apt_cve_verify", tool_names)

    def test_plan_llm_driven_with_fallback(self):
        """验证 plan_attack 函数签名 + fallback 调用路径存在"""
        from security_log_analyzer.apt_core import plan_attack, PLAN_ATTACK_SYSTEM_PROMPT

        # 验证 system prompt 包含"先分析再规划缓存优先"
        self.assertIn("先分析", PLAN_ATTACK_SYSTEM_PROMPT)
        self.assertIn("缓存优先", PLAN_ATTACK_SYSTEM_PROMPT)

        # 验证 plan_attack 接受 assistant_factory 参数
        state = AptSimulationState(
            targets=[AptTarget(id="t1", host="10.0.0.1", vector="firewall_breach")],
        )
        features = {
            "open_ports": [{"port": 80, "service": "http"}],
            "categories": {"http": [80]},
        }
        # 不调LLM，直接验证函数可被导入调用
        import inspect
        sig = inspect.signature(plan_attack)
        params = list(sig.parameters.keys())
        self.assertIn("state", params)
        self.assertIn("target_features", params)
        self.assertIn("assistant_factory", params)

    def test_plan_fallback_fn_direct(self):
        """直接测试 _plan_attack_fallback 函数"""
        from security_log_analyzer.apt_core import _plan_attack_fallback

        features = {
            "open_ports": [
                {"port": 445, "service": "microsoft-ds"},
                {"port": 2375, "service": "docker"},
            ],
            "categories": {"smb": [445], "docker": [2375]},
        }
        plan = _plan_attack_fallback("10.0.0.5", features)
        self.assertTrue(plan["fallback"])
        steps = plan["phases"]["initial_access"]
        tools = [s["tool"] for s in steps]
        self.assertIn("apt_smb_enum", tools)
        self.assertIn("apt_docker_exploit", tools)

    def test_generate_tool_from_plan(self):
        """_generate_tool_from_plan — 缓存命中路径"""
        from security_log_analyzer.apt_core import _generate_tool_from_plan
        from security_log_analyzer.apt_tools import tool_signature, store_tool_cache

        state = AptSimulationState(
            targets=[AptTarget(id="t1", host="10.0.0.1")],
        )

        # 预填充缓存，确保走缓存命中路径（不调LLM）
        sig = tool_signature("modbus_probe", "10.0.0.1", "modbus", "1.0")
        store_tool_cache(sig, "def modbus_probe(target, port, **kw): return {'success': True}", {})

        llm_plan = {
            "need_new_tool": True,
            "new_tool_spec": {
                "tool_name": "modbus_probe",
                "description": "Modbus TCP 协议探测工具",
                "target_service": "modbus",
                "target_version": "1.0",
            },
        }
        result = _generate_tool_from_plan(llm_plan, state, "10.0.0.1")
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("cached"), "预填充缓存后应走缓存命中路径")
        self.assertEqual(result.get("signature"), sig)


# ── 3. 横向移动工具 ──────────────────────────────────────

class TestLateralMovement(unittest.TestCase):
    """测试横向移动工具"""

    def test_psexec_simulated(self):
        """PsExec 模拟执行"""
        r = apt_psexec(
            host="10.0.0.1", username="admin", password="pass",
            target_host="10.0.0.2", command="whoami",
        )
        self.assertTrue(r.get("success") or r.get("simulated"))

    def test_psexec_no_target(self):
        """无目标时报错"""
        r = apt_psexec(host="10.0.0.1", username="admin", password="pass", target_host="")
        self.assertFalse(r["success"])
        self.assertIn("target_host", r.get("error", ""))

    def test_wmi_simulated(self):
        """WMI 模拟执行"""
        r = apt_wmi_exec(
            host="10.0.0.1", username="admin", password="pass",
            target_host="10.0.0.2",
        )
        self.assertTrue(r.get("success") or r.get("simulated"))

    def test_schtasks_simulated(self):
        """计划任务模拟执行"""
        r = apt_schtasks(
            host="10.0.0.1", username="admin", password="pass",
            target_host="10.0.0.2", command="cmd /c whoami",
        )
        self.assertTrue(r.get("success") or r.get("simulated"))

    def test_pass_the_hash_invalid(self):
        """无效 NTLM Hash 被拒绝"""
        r = apt_pass_the_hash(host="10.0.0.1", nt_hash="short", target_host="10.0.0.2")
        self.assertFalse(r["success"])
        self.assertIn("需要有效的 NTLM Hash", r.get("error", ""))

    def test_pass_the_hash_valid_hash(self):
        """有效格式的 Hash 可执行（模拟）"""
        r = apt_pass_the_hash(
            host="10.0.0.1",
            nt_hash="aad3b435b51404eeaad3b435b51404ee",
            target_host="10.0.0.2",
            username="Administrator",
        )
        self.assertTrue(r.get("success") or r.get("simulated"))
        self.assertEqual(r["method"], "pass_the_hash")

    def test_ssh_key_reuse_simulated(self):
        """SSH 密钥复用模拟"""
        r = apt_ssh_key_reuse(
            host="10.0.0.1", username="root", password="toor",
            target_host="10.0.0.2", target_user="root",
        )
        self.assertTrue(r.get("success") or r.get("simulated"))

    def test_ssh_key_reuse_no_target(self):
        """无目标时报错"""
        r = apt_ssh_key_reuse(host="10.0.0.1", username="root", password="toor", target_host="")
        self.assertIn("target_host", r.get("error", ""))

    def test_internal_scan(self):
        """内网扫描 — 即使无存活也返回成功"""
        r = apt_internal_scan(
            host="10.0.0.1", username="test", password="test",
            subnet="192.168.1.0/30",
        )
        self.assertTrue(r["success"])
        self.assertIn("discovered_hosts", r)

    def test_internal_scan_invalid_subnet(self):
        """无效子网格式报错"""
        r = apt_internal_scan(
            host="10.0.0.1", username="test", password="test",
            subnet="not-a-subnet",
        )
        self.assertIn("error", r)


# ── 4. 宏文档生成 ────────────────────────────────────────

class TestMacroGeneration(unittest.TestCase):
    """测试宏文档生成"""

    def test_generate_in_memory(self):
        """不指定 output_path 时返回宏代码"""
        r = generate_macro_doc("test_org", "http://127.0.0.1:8080/capture")
        self.assertTrue(r["success"])
        self.assertIn("Auto_Open", r.get("macro_code", ""))
        self.assertIn("COMPUTERNAME", r.get("macro_code", ""))

    def test_generate_to_file(self):
        """指定 output_path 时写入文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "test_attachment")
            r = generate_macro_doc("test", "http://127.0.0.1:8080/capture", output_path=out)
            self.assertTrue(r["success"])
            self.assertTrue(os.path.exists(r.get("output_path", "")))

    def test_missing_c2_url(self):
        """缺少 c2_url 时报错"""
        r = generate_macro_doc("test", "")
        self.assertFalse(r["success"])
        self.assertIn("c2_url", r.get("error", ""))


# ── 5. C2 监听器 ─────────────────────────────────────────

class TestC2Listener(unittest.TestCase):
    """测试 C2 监听器"""

    def test_get_local_ip(self):
        """获取本机 IP"""
        ip = get_local_ip()
        self.assertIsInstance(ip, str)
        self.assertTrue(len(ip) > 0)

    def test_captured_hosts_clear(self):
        """清空回调记录"""
        clear_captured_hosts()
        from security_log_analyzer.c2_listener import captured_hosts
        self.assertEqual(len(captured_hosts), 0)

    def test_config_constants(self):
        """C2 配置常量"""
        self.assertIsInstance(C2_HOST, str)
        self.assertIsInstance(C2_PORT, int)
        self.assertIsInstance(C2_ENABLED, bool)


# ── 6. 数据结构 ──────────────────────────────────────────

class TestDataStructures(unittest.TestCase):
    """测试新增数据结构"""

    def test_plan_step(self):
        step = PlanStep(tool="ssh_brute", params={"host": "1.2.3.4"}, order=1, on_failure="continue")
        self.assertEqual(step.tool, "ssh_brute")
        self.assertEqual(step.order, 1)
        self.assertEqual(step.on_failure, "continue")

    def test_attack_plan(self):
        plan = AttackPlan(plan_id="abc123", target_signature="sig1", rationale="test")
        self.assertEqual(plan.plan_id, "abc123")
        self.assertEqual(plan.target_signature, "sig1")

    def test_tool_cache_entry(self):
        entry = ToolCacheEntry(signature="sig1", tool_name="ssh_brute",
                               tool_code="print(1)", hit_count=1)
        self.assertEqual(entry.signature, "sig1")
        self.assertEqual(entry.hit_count, 1)

    def test_phishing_callback(self):
        cb = PhishingCallback(hostname="PC01", username="admin",
                              internal_ip="192.168.1.100", timestamp="2025-01-01")
        self.assertEqual(cb.hostname, "PC01")
        self.assertEqual(cb.username, "admin")

    def test_state_new_fields(self):
        """AptSimulationState 包含新增字段"""
        state = AptSimulationState(targets=[AptTarget(id="t1", host="1.2.3.4")])
        self.assertIsNone(state.attack_plan)
        self.assertIsInstance(state.tool_cache, dict)
        self.assertIsInstance(state.phishing_callbacks, list)


if __name__ == "__main__":
    unittest.main()
