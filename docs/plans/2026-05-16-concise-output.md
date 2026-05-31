# Concise Output Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce the default report and compare output to a concise summary while keeping the key security conclusion, evidence, and standards references.

**Architecture:** Keep the analysis pipeline unchanged. Add a compact report renderer that reuses existing analysis data but emits fewer sections and shorter bullet points. Preserve the detailed data in the analysis model so future verbose output can still be restored if needed.

**Tech Stack:** Python 3.13, unittest, existing `security_log_analyzer` report and CLI modules.

### Task 1: Add concise report coverage

**Files:**
- Modify: `tests/test_report.py`

**Step 1: Write the failing test**

```python
def test_build_security_report_is_concise():
    ...
```

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_report -v`

Expected: fail because the report still includes the long verbose sections.

**Step 3: Write minimal implementation**

No code yet.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_report -v`

Expected: pass after the report is shortened.

### Task 2: Simplify default report rendering

**Files:**
- Modify: `security_log_analyzer/report.py`
- Modify: `security_log_analyzer/__main__.py`

**Step 1: Write the failing test**

```python
def test_main_prints_concise_report_by_default():
    ...
```

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_cli -v`

Expected: fail because the report still renders many sections.

**Step 3: Write minimal implementation**

Trim the report to the minimal sections needed for a demo:
- analysis object
- summary
- standards references
- agent verdict
- risk level
- top evidence
- one short recommendation block

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_cli -v`

Expected: pass.

### Task 3: Verify real CLI output

**Files:**
- None

**Step 1: Run the concise local report**

Run: `python -m security_log_analyzer test_logs\web_sql_injection.log`

Expected: a short report with the key conclusion and evidence only.

**Step 2: Run the concise agent report**

Run: `python -m security_log_analyzer test_logs\web_sql_injection.log --agent`

Expected: the same compact shape, with the agent verdict included.

**Step 3: Run compare mode**

Run: `python -m security_log_analyzer test_logs\web_sql_injection.log --compare`

Expected: a short side-by-side comparison instead of a long verbose block.
