# RAG Security Analysis Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a lightweight local RAG layer so the project can retrieve relevant OWASP/MITRE/NIST guidance for each log anomaly and feed that context into both the Python judgment path and the Qwen/MiMo agent path.

**Architecture:** Keep the current evidence layer unchanged: parse logs, extract findings, and compute baseline risk in Python. Add a standards corpus and retrieval layer that maps findings to the most relevant security guidance, then use those retrieved passages to strengthen the local standards assessment and the agent prompt. The agent remains the final semantic judge, but its output is constrained by the same retrieved standard context and a deterministic risk floor from the local side.

**Tech Stack:** Python 3.13, `unittest`, `dataclasses`, `argparse`, local file-based corpus, lightweight vector retrieval or lexical retrieval fallback, existing MiMo/Qwen agent stack

### Task 1: Define the RAG data model and corpus layout

**Files:**
- Create: `security_log_analyzer/rag/__init__.py`
- Create: `security_log_analyzer/rag/corpus.py`
- Create: `security_log_analyzer/rag/schemas.py`
- Create: `data/standards/owasp/*.md`
- Create: `data/standards/mitre/*.md`
- Create: `data/standards/nist/*.md`

**Step 1: Write the failing test**

Add tests that assert:
- a corpus loader can enumerate standard documents
- a chunk schema stores `source`, `framework`, `section`, `chunk_text`, and `tags`
- the repo has at least one document per framework family

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_rag_corpus -v`
Expected: fail because the RAG package and corpus files do not exist yet.

**Step 3: Write minimal implementation**

Implement the corpus loader and chunk schema, and add a small set of authoritative standard documents or markdown excerpts that the project can index locally.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_rag_corpus -v`
Expected: PASS

### Task 2: Build retrieval and ranking for security findings

**Files:**
- Create: `security_log_analyzer/rag/retriever.py`
- Create: `security_log_analyzer/rag/index.py`
- Modify: `security_log_analyzer/standards.py`
- Modify: `tests/test_rag_retrieval.py`

**Step 1: Write the failing test**

Add tests that map representative findings to retrieved standard snippets:
- `sql_injection` should retrieve OWASP injection guidance and MITRE public-facing exploit guidance
- `bruteforce` should retrieve OWASP authentication failure guidance and MITRE T1110
- `off_hours_access` should retrieve NIST monitoring / access-control guidance

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_rag_retrieval -v`
Expected: fail because retrieval and ranking do not exist yet.

**Step 3: Write minimal implementation**

Implement a small retrieval layer:
- lexical scoring first
- optional embedding hook later
- deterministic tie-breaking by framework priority and section priority

Have `build_standards_assessment()` consume retrieved chunks instead of relying only on hardcoded mappings.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_rag_retrieval -v`
Expected: PASS

### Task 3: Feed retrieved context into the Python and agent pipelines

**Files:**
- Modify: `security_log_analyzer/agent.py`
- Modify: `security_log_analyzer/agentic.py`
- Modify: `security_log_analyzer/models.py`
- Modify: `security_log_analyzer/report.py`
- Modify: `security_log_analyzer/qwen_assistant.py`
- Modify: `tests/test_agent.py`
- Modify: `tests/test_report.py`
- Modify: `tests/test_qwen_assistant.py`

**Step 1: Write the failing test**

Add tests that assert:
- `SecurityAnalysis` carries retrieved standards context
- the report shows retrieved standard snippets, not only labels
- the agent prompt includes retrieved evidence plus retrieved standard excerpts
- the agent JSON schema includes references back to the retrieved standard chunks

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_agent tests.test_report tests.test_qwen_assistant -v`
Expected: fail because the new RAG fields are not wired through yet.

**Step 3: Write minimal implementation**

Thread the retrieval results through:
- `findings -> retrieval query -> retrieved chunks`
- `retrieved chunks -> standards assessment -> risk floor`
- `retrieved chunks -> agent prompt -> final JSON`
- `retrieved chunks -> report section`

Keep the current deterministic Python evidence pipeline intact.

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_agent tests.test_report tests.test_qwen_assistant -v`
Expected: PASS

### Task 4: Add corpus update and validation tooling

**Files:**
- Create: `scripts/build_rag_index.py`
- Create: `scripts/validate_standards_corpus.py`
- Modify: `README.md` or project usage docs
- Modify: `tests/test_rag_tools.py`

**Step 1: Write the failing test**

Add tests that assert:
- the corpus validator catches malformed chunks
- the index build script can regenerate the retrieval artifact
- the project can run with a missing optional vector backend by falling back to lexical retrieval

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_rag_tools -v`
Expected: fail because the tooling does not exist yet.

**Step 3: Write minimal implementation**

Implement:
- corpus validation
- offline index generation
- fallback retrieval path when a vector dependency is unavailable

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_rag_tools -v`
Expected: PASS

### Task 5: Benchmark and compare the two analysis paths

**Files:**
- Modify: `security_log_analyzer/__main__.py`
- Create: `tests/test_rag_compare.py`

**Step 1: Write the failing test**

Add tests that compare:
- current non-RAG standards path
- new RAG-enhanced path

Validate on representative logs from `test_logs/` that:
- clear attacks stay high
- normal logs stay low
- borderline logs become more explainable

**Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_rag_compare -v`
Expected: fail because the comparison mode does not yet know about RAG.

**Step 3: Write minimal implementation**

Add a compare mode that prints:
- baseline Python score
- RAG-enhanced score
- agent score
- standards references used
- delta and confidence notes

**Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_rag_compare -v`
Expected: PASS

### Task 6: Full regression

**Files:**
- None

**Step 1: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: PASS

**Step 2: Run a representative RAG comparison**

Run:
```powershell
python -m security_log_analyzer test_logs --compare
```
Expected: the report shows retrieved standards context, and the agent path remains stable for the existing logs.
