# Standard Layer Agent Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a standards layer that maps findings to OWASP/MITRE/NIST-style references and feeds those references into the agent-driven judgment and reports.

**Architecture:** Keep the current evidence layer intact: parse logs, extract findings, and build summary data in Python. Add a standards module that maps each finding kind to one or more industry references and derives a standard-based severity hint. Feed those references into the Qwen/MiMo prompt and output schema so the agent makes its final decision inside a constrained standards frame, then surface the same standards in the report.

**Tech Stack:** Python 3.13, `unittest`, `dataclasses`, `argparse`

### Task 1: Add standards coverage tests

**Files:**
- Modify: `tests/test_report.py`
- Create: `tests/test_standards.py`

**Step 1: Write the failing test**

Add a test that maps representative findings to standard references and a report test that expects a standards section in the final output.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_standards tests.test_report -v`
Expected: fail because the standards module and report section do not exist yet.

**Step 3: Write minimal implementation**

Add the standards mapping module and expose it in the report.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_standards tests.test_report -v`
Expected: PASS

### Task 2: Feed standards into the agent judgment path

**Files:**
- Modify: `security_log_analyzer/models.py`
- Modify: `security_log_analyzer/agent.py`
- Modify: `security_log_analyzer/agentic.py`
- Modify: `security_log_analyzer/qwen_assistant.py`

**Step 1: Write the failing test**

Add a test that checks the analysis object carries standard references and that the agent prompt/schema requests standard-aware output.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_agent tests.test_qwen_assistant -v`
Expected: fail because the new standard fields and prompt constraints are not wired in yet.

**Step 3: Write minimal implementation**

Add standard references to the analysis model, pass them into the agent, and require them in the final JSON contract.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_agent tests.test_qwen_assistant -v`
Expected: PASS

### Task 3: Verify full regression

**Files:**
- None

**Step 1: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: PASS

**Step 2: Run a representative compare check**

Run:
```powershell
python -m security_log_analyzer test_logs --compare
```
Expected: report includes standards-aware agent judgment without breaking batch mode.
