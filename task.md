# Roadmap Enhancements & Hardware Optimization Tasks

- [ ] **Phase 1: Hardware & Configuration Tuning**
  - [x] Modify `config.yaml` to change `local_model` to `"llama3.2:3b"` or `"qwen2.5:3b"` for GPU offloading on GTX 1650.
  - [ ] Validate configuration loading tests.

- [ ] **Phase 2: Target-Based SQLite Session Partitioning**
  - [ ] Modify `agent/ptt.py` to support dynamic database path names based on sanitized target IP.
  - [ ] Update `agent/main.py` ReAct loop to instantiate `PTTStore` dynamically.
  - [ ] Run existing PTT unit tests to ensure compatibility.

- [ ] **Phase 3: Automated HackTricks Ingestion (RAG)**
  - [ ] Update `agent/rag/ingest.py` to support `--download` flag.
  - [ ] Implement ZIP downloader and auto-extractor for HackTricks master branch markdown files.
  - [ ] Create unit tests in `tests/test_rag.py` to verify RAG store additions and queries.

- [ ] **Phase 4: ReAct Loop RAG Integration**
  - [ ] Import and lazy-initialize `RAGStore` in `agent/main.py`.
  - [ ] Retrieve relevant context during CVE / service exploitation step.
  - [ ] Pass the retrieved `rag_context` to `generate_exploit` in `agent/agents/exploiter.py`.

- [ ] **Phase 5: HTML/PDF Dual Report Generation**
  - [ ] Add `xhtml2pdf` dependency to `requirements.txt` (or implement clean fallback).
  - [ ] Modify `agent/report/generator.py` to support PDF rendering.
  - [ ] Update `config.yaml` to define report output formats.
  - [ ] Create `tests/test_report.py` to verify HTML and PDF rendering.

- [ ] **Phase 6: Verification & Polish**
  - [ ] Run full test suite with `python -m pytest tests/ -v`.
  - [ ] Run a test loop of the agent to verify dynamic target DBs, RAG queries, and dual-format reports.
