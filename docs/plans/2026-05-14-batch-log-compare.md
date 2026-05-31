# Batch Log Compare Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow the CLI to analyze every `.log` file under `test_logs` in local mode, agent mode, or side-by-side comparison mode.

**Architecture:** Keep the existing single-file analysis path intact. Add a small batch layer in the CLI that can detect directory inputs, enumerate log files, and run either one mode or both modes per file. Add a compact comparison formatter so the user can see local versus agent risk side by side without changing the core analysis engine.

**Tech Stack:** Python 3.13, `argparse`, `pathlib`, `unittest`

### Task 1: Add batch CLI coverage

**Files:**
- Modify: `tests/test_cli.py`

**Step 1: Write the failing test**

Add tests for a directory input that runs all `.log` files, and for compare mode that invokes both local and agent analysis per file.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_cli -v`
Expected: fail because the CLI does not handle directory batch or compare mode yet.

**Step 3: Write minimal implementation**

Add CLI support in `security_log_analyzer/__main__.py`.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_cli -v`
Expected: PASS

### Task 2: Implement batch analysis entrypoints

**Files:**
- Modify: `security_log_analyzer/__main__.py`

**Step 1: Write the failing test**

Use the new CLI tests as the failing specification.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_cli -v`
Expected: fail before code changes.

**Step 3: Write minimal implementation**

Add directory detection, recursive `.log` file enumeration, compare-mode execution, and concise comparison output.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_cli -v`
Expected: PASS

### Task 3: Verify full regression

**Files:**
- None

**Step 1: Run the related test suite**

Run: `python -m unittest discover -s tests -v`
Expected: PASS

**Step 2: Manual smoke test**

Run:
```powershell
python -m security_log_analyzer test_logs --compare
```
Expected: print a comparison summary for every `.log` file.
