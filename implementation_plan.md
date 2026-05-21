# Autonomous AI Pentesting Agent — Roadmap & Hardware Optimization Plan

This implementation plan outlines how we will deliver high-value roadmap enhancements and refactor the codebase to run smoothly and at **zero cost** on a budget desktop setup:
* **CPU**: Intel Core i3-9100F (4 cores, 4 threads)
* **RAM**: 16 GB DDR4
* **GPU**: NVIDIA GeForce GTX 1650 (4 GB VRAM)

---

## 🖥️ Hardware & Cost Optimization Strategy

To make the agent run fast and efficiently on a **GTX 1650 (4 GB VRAM)** and **i3-9100F CPU** with **zero API cost**, we will implement the following optimizations:

### 1. Local Model Optimization (Fitting in 4 GB VRAM)
* **The Problem**: A standard 8B model (like `llama3.1:8b`) requires ~4.8 GB of memory. On a 4 GB GPU, Ollama is forced to spill layers into system RAM. On a 4-core i3 CPU, this causes extremely slow inference (~1–3 tokens per second).
* **The Solution**: 
  * We will switch the default local model in `config.yaml` to **`llama3.2:3b`** or **`qwen2.5:1.5b` / `qwen2.5:3b`**.
  * A 3B quantized model requires only **~2.0 GB of VRAM**. It will fit **entirely within the GTX 1650 VRAM** with ample headroom (2 GB remaining) for Windows/display.
  * This shifts local execution entirely to the GPU, increasing inference speed to **~25–40 tokens per second** (a 10x speedup), completely removing CPU bottlenecks.

### 2. Offloading Complex Reasoning to Cloud Free Tiers
* **The Strategy**: Keep local models small and fast, using them strictly for fast text extraction, tool command parsing, and basic formatting.
* **The Cloud Gate**: Offload all high-level strategy, CVE research, and exploit planning to **Gemini 2.5 Flash** using Google's **Free Tier API Key** (15 Requests per Minute, 1,500 Requests per Day).
* **Cost**: **$0.00 / month** (entirely within the free tier).
* **Local Hardware Impact**: **Zero** (remote hosting removes CPU/GPU rendering loads for complex prompts).

### 3. Subprocess & Memory Refactoring
* **Output Truncation**: Capping raw tool outputs in memory buffers to avoid memory spikes on the 4-core i3.
* **Subprocess Management**: Enforcing strict timeouts (`max_subprocess_timeout: 300`) to prevent runaway processes from consuming CPU cycles.

---

## Proposed Changes & Tasks

### Phase 1: Local RAG & HackTricks Ingestion
We will automate the ingestion of HackTricks data and hook up RAG context queries directly to the ReAct loop.

#### [MODIFY] [ingest.py](file:///C:/Users/Peeranat/Downloads/Ai%20penetrationv2/Ai%20penetration/agent/rag/ingest.py)
* Add a `--download` flag to fetch the lightweight official HackTricks markdown documentation ZIP archive from GitHub.
* Programmatically extract, chunk, and embed the documentation locally into ChromaDB using Ollama's `nomic-embed-text` (which runs extremely fast on GTX 1650).

#### [MODIFY] [main.py](file:///C:/Users/Peeranat/Downloads/Ai%20penetrationv2/Ai%20penetration/agent/main.py)
* Initialize `RAGStore` at the start of the `react_loop`.
* Prior to running the exploit stage, query the RAG database for matching CVE or service details.
* Pass the extracted `rag_context` to the `generate_exploit` function to guide Gemini's generation.

---

### Phase 2: Refactoring & Hardware Configuration Updates
We will clean up the default configuration file to use highly optimized, lightweight local models that run entirely inside the GPU's 4 GB VRAM.

#### [MODIFY] [config.yaml](file:///C:/Users/Peeranat/Downloads/Ai%20penetrationv2/Ai%20penetration/config.yaml)
* Set `local_model` to `"llama3.2:3b"` or `"qwen2.5:3b"` (highly optimized for 4 GB cards).
* Configure the default RAG chunk sizes and embedding models for optimal lookup speed.

---

### Phase 3: Dual Report Generation (HTML & PDF)
We will add high-fidelity PDF report exporting.

#### [MODIFY] [generator.py](file:///C:/Users/Peeranat/Downloads/Ai%20penetrationv2/Ai%20penetration/agent/report/generator.py)
* Integrate `xhtml2pdf` to output premium PDF reports (`data/report.pdf`) side-by-side with the HTML report.

---

### Phase 4: Multi-Target Session Support
We will partition SQLite databases by target IP to enable isolated runs.

#### [MODIFY] [ptt.py](file:///C:/Users/Peeranat/Downloads/Ai%20penetrationv2/Ai%20penetration/agent/ptt.py)
* Update `PTTStore` initialization to generate database paths dynamically (e.g., `data/ptt_10_10_10_100.db`) using the active target IP.

---

## Verification Plan

### Automated Tests
* Add `tests/test_rag.py` to verify local RAG query speed and correctness.
* Add `tests/test_report.py` to ensure PDF compilation doesn't crash on long tables.
* Execute unit tests:
  ```bash
  python -m pytest tests/ -v
  ```

### Manual Verification
1. Verify Ollama VRAM usage using the Windows Task Manager (GPU Dedicated Memory) or running `nvidia-smi` to ensure the model sits entirely in VRAM.
2. Run ingestion using `python -m agent.rag.ingest --download` to verify automated extraction.
3. Confirm that the run outputs target-specific databases and both HTML and PDF reports.
