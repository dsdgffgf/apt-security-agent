# RAG Corpus Expansion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the local standards corpus into a broader OWASP / MITRE / NIST / CWE reference set and verify the full agentic analysis flow still runs end to end.

**Architecture:** Keep the existing evidence pipeline intact. Add richer local standard documents and wire the standard-layer mappings to surface the broader references in retrieval, reports, and agent prompts. Preserve deterministic fallback behavior and validate the real MiMo-backed path against representative logs.

**Tech Stack:** Python 3.13, `unittest`, local markdown corpus, existing RAG lexical retriever, Qwen-Agent, Xiaomi MiMo Anthropic endpoint

### Task 1: Expand the standards corpus

**Files:**
- Create: `data/standards/cwe/cwe-summary.md`
- Create: `data/standards/owasp/owasp-api-security.md`
- Create: `data/standards/mitre/mitre-credential-access.md`
- Create: `data/standards/nist/nist-response.md`

**Step 1: Write the failing test**

Add tests that assert the corpus now includes a `cwe` framework family and the new documents are discoverable by the corpus loader.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_rag_corpus tests.test_rag_tools -v`
Expected: fail because the new corpus documents do not exist yet.

**Step 3: Write minimal implementation**

Add compact markdown summaries for:
- CWE injection / traversal / XSS / authentication weakness patterns
- OWASP API security concerns
- MITRE credential-access guidance
- NIST response / detection guidance

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_rag_corpus tests.test_rag_tools -v`
Expected: PASS

### Task 2: Surface richer standard references in the standards layer

**Files:**
- Modify: `security_log_analyzer/standards.py`
- Modify: `tests/test_standards.py`

**Step 1: Write the failing test**

Add assertions that representative findings also surface CWE references where appropriate, and that retrieval can return CWE chunks for injection and authentication scenarios.

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_standards tests.test_rag_retrieval -v`
Expected: fail before the rules and queries mention CWE.

**Step 3: Write minimal implementation**

Add CWE references and matching query hints for the relevant finding kinds.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_standards tests.test_rag_retrieval -v`
Expected: PASS

### Task 3: Run the full analysis flow

**Files:**
- None

**Step 1: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: PASS

**Step 2: Run representative agent analyses**

Run:
```powershell
conda run --no-capture-output -n security-log-analyzer python -m security_log_analyzer test_logs\web_sql_injection.log --agent
conda run --no-capture-output -n security-log-analyzer python -m security_log_analyzer test_logs\ssh_bruteforce.log --agent
```
Expected: both flows complete with the MiMo-backed agent path and render the expanded standard references.
