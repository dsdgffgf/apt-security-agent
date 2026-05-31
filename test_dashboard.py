"""Quick test of the dashboard backend without Flask server"""
import json
from web_dashboard.app import EventCollector, _run_simulation_with_events

print("=== Test 1: Firewall Breach ===")
c = EventCollector("test_fw")
result = _run_simulation_with_events("test_fw", "scanme.nmap.org", "firewall_breach", c)
state = result["state"]
print(f"  vector={state['vector']}, awareness={state['blue_team_awareness']}/100, targets={len(state['targets'])}")
for p in result["phase_results"]:
    print(f"  [{p['status']}] {p['phase']}: {p.get('summary','')[:50]}")

print("\n=== Test 2: Supply Chain (dual target) ===")
c2 = EventCollector("test_sc")
result2 = _run_simulation_with_events("test_sc", "b-tech.com.cn", "supply_chain", c2, "c-manufacturing.com")
state2 = result2["state"]
print(f"  vector={state2['vector']}, awareness={state2['blue_team_awareness']}/100, targets={len(state2['targets'])}")
for t in state2["targets"]:
    print(f"  target: {t['host']} compromised={t['compromised']}")
for p in result2["phase_results"]:
    print(f"  [{p['status']}] {p['phase']}: {p.get('summary','')[:50]}")

print("\n=== Test 3: Phishing ===")
c3 = EventCollector("test_ph")
result3 = _run_simulation_with_events("test_ph", "c-vocational.edu.cn", "phishing", c3)
state3 = result3["state"]
print(f"  vector={state3['vector']}, awareness={state3['blue_team_awareness']}/100")
for p in result3["phase_results"]:
    print(f"  [{p['status']}] {p['phase']}: {p.get('summary','')[:50]}")

print("\nALL TESTS PASSED")
