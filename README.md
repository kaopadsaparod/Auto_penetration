# 🤖 Auto Penetration — AI Pentesting Agent

> **Autonomous Penetration Testing Agent** designed for **$0/month** operation.  
> Built for students, researchers, and CTF players on a zero budget.

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-62%20passed-brightgreen.svg)](#testing)

---

## 📌 Overview

A fully autonomous pentesting agent that uses a **Hybrid LLM architecture**:

| Component | Model | Cost | Role |
|-----------|-------|------|------|
| **Local LLM (80%)** | `llama3.2:3b` via Ollama | **FREE** | Parsing, Routing, Reasoning (optimised for GTX 1650/4GB VRAM) |
| **Cloud LLM (20%)** | `Gemini 2.5 Flash` (Free Tier) | **FREE** | Attack planning, Exploit generation |
| **Embeddings** | `nomic-embed-text` via Ollama | **FREE** | RAG knowledge base |
| **Vector DB** | ChromaDB (local) | **FREE** | Pentest knowledge storage |

### 💰 Total Monthly Cost: **$0**

The agent uses Gemini 2.5 Flash on the **free tier** with strict budget controls (max 20 API calls/run, max 50K tokens). All heavy lifting (parsing, reasoning) runs locally via Ollama.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  ReAct Loop                     │
│  (Reason → Act → Observe → Repeat)             │
├─────────────┬─────────────┬─────────────────────┤
│ Enumerator  │  Reasoner   │  Planner            │
│ (Ollama)    │  (Ollama)   │  (Gemini Flash)     │
│ FREE        │  FREE       │  FREE TIER          │
├─────────────┴─────────────┴─────────────────────┤
│              Tool Dispatcher                    │
│  nmap │ gobuster │ sqlmap │ metasploit │ shell  │
├─────────────────────────────────────────────────┤
│          Safety Guardrails (HITL)               │
│  Scope Guard │ Blocklist │ Budget │ Approval    │
├─────────────────────────────────────────────────┤
│              PTT Store (SQLite)                 │
│  Pentest Tree — full attack path traceability   │
└─────────────────────────────────────────────────┘
```

### ReAct Loop Flow

1. **OBSERVE** — Get next pending node from PTT
2. **SAFETY** — Validate command through guardrails
3. **ACT** — Execute the tool (nmap, gobuster, etc.)
4. **PARSE** — Extract structured findings (Ollama, FREE)
5. **REASON** — Evaluate significance (Ollama, FREE)
6. **PLAN** — Escalate to Gemini if needed (FREE TIER)
7. **EXPAND** — Create child nodes in PTT
8. **REPEAT** — Until done or budget exhausted

---

## 📁 Project Structure

```
Auto_penetration/
├── agent/
│   ├── __init__.py
│   ├── main.py              # ReAct loop orchestrator
│   ├── config.py             # YAML config loader + validator
│   ├── logger.py             # Dual handler logging (console + file)
│   ├── ptt.py                # Pentest Tree — SQLite persistence
│   ├── agents/
│   │   ├── llm_client.py     # Unified Ollama + Gemini client
│   │   ├── enumerator.py     # Scan output parser (FREE)
│   │   ├── reasoner.py       # Finding evaluator (FREE)
│   │   ├── planner.py        # Attack strategist (Gemini)
│   │   └── exploiter.py      # Exploit generator (Gemini, gated)
│   ├── tools/
│   │   ├── base.py           # Input validation + subprocess wrapper
│   │   ├── nmap_tool.py      # Nmap with XML parsing
│   │   ├── gobuster_tool.py  # Directory brute-force
│   │   ├── sqlmap_tool.py    # SQL injection scanner
│   │   ├── msf_tool.py       # Metasploit module runner
│   │   └── shell_tool.py     # Generic command executor
│   ├── safety/
│   │   └── guardrails.py     # Scope guard, blocklist, HITL
│   ├── report/
│   │   └── generator.py      # Premium glassmorphic HTML + high-contrast PDF reports
│   └── rag/
│       ├── embedder.py       # ChromaDB + Ollama embeddings
│       └── ingest.py         # HackTricks knowledge ingestion
├── tests/
│   ├── test_ptt.py           # PTT CRUD + tree operations
│   ├── test_safety.py        # Scope, blocklist, HITL tests
│   ├── test_tools.py         # Input validation + XML parsing
│   ├── test_rag.py           # Ingestion + Chroma query validation
│   └── test_report.py        # Glassmorphic HTML + PDF rendering tests
├── config.yaml               # Agent configuration
├── Dockerfile                # Container with pentesting tools
├── docker-compose.yml        # Agent + optional target services
├── requirements.txt          # Python dependencies
└── .gitignore
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **Ollama** installed and running (`ollama serve`)
- **Gemini API Key** (free from [Google AI Studio](https://aistudio.google.com/))

### 1. Clone & Install

```bash
git clone https://github.com/kaopadsaparod/Auto_penetration.git
cd Auto_penetration
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Pull Ollama Models (FREE)

```bash
ollama pull llama3.2:3b
ollama pull nomic-embed-text
```

### 3. Set Gemini API Key

```bash
export GEMINI_API_KEY="your-free-tier-key-here"
# Windows: set GEMINI_API_KEY=your-free-tier-key-here
```

### 4. Configure Target

Edit `config.yaml`:
```yaml
target:
  ip: "10.10.10.100"
  allowed_ips: ["10.10.10.0/24"]
```

### 5. Run

```bash
# Direct
python -m agent.main

# Via Docker (recommended for pentesting tools)
docker compose up --build
```

---

## 🔒 Safety Features

| Guard | Description |
|-------|-------------|
| **Scope Guard** | CIDR-based IP validation — agent CANNOT touch IPs outside allowed range |
| **Blocklist** | Absolute block on destructive commands (`rm -rf`, `mkfs`, `dd`, etc.) |
| **HITL** | Human approval required for exploit/shell commands |
| **Budget Guard** | Hard limits on API calls and token usage |
| **Input Sanitization** | All tool inputs validated against shell injection |
| **List-based Subprocess** | Never uses `shell=True` — prevents command injection |

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Expected: 62 tests passed (~6.9s)
```

Test coverage includes:
- PTT CRUD operations + tree traversal
- Input validation (IP, port, URL, shell injection)
- Nmap XML parsing
- Scope guard (CIDR matching)
- Blocklist and destructive command detection
- HITL approval flow
- ChromaDB RAG context lookup and automated ingestion
- Premium HTML and PDF report generation compatibility

---

## 💰 Cost Breakdown

| Service | Tier | Monthly Cost |
|---------|------|-------------|
| Ollama (local) | Self-hosted | **$0** |
| Gemini 2.5 Flash | Free tier (15 RPM) | **$0** |
| ChromaDB | Local | **$0** |
| nomic-embed-text | Via Ollama | **$0** |
| **Total** | | **$0/month** |

### Budget Controls
- Max **20 Gemini API calls** per run
- Max **50,000 tokens** per run
- Max **15 ReAct iterations** per run
- Gemini only called for:
  - Attack planning (1 call/session)
  - Exploit generation (only when CVE found)

---

## 📝 Configuration Reference

See [`config.yaml`](config.yaml) for all settings:

- `target` — IP, allowed CIDRs, allowed ports
- `budget` — Token limits, API call limits, iteration caps
- `safety` — HITL toggle, blocked commands, destructive keywords
- `llm` — Model names, Ollama host, Gemini API key env var
- `rag` — ChromaDB path, embedding model, chunk size

---

## 🛣️ Roadmap

- [x] Core ReAct loop architecture
- [x] PTT (Pentest Tree) with SQLite persistence
- [x] Tool wrappers (nmap, gobuster, sqlmap, msf, shell)
- [x] Safety guardrails (scope, blocklist, HITL)
- [x] Hybrid LLM client (Ollama + Gemini)
- [x] RAG infrastructure (ChromaDB + nomic-embed-text)
- [x] Input validation and command injection prevention
- [x] Comprehensive test suite (62 tests)
- [x] RAG ingestion with HackTricks data (`python -m agent.rag.ingest --download`)
- [x] HTML/PDF report generation (`xhtml2pdf` compliant dual reports)
- [x] Target-based SQLite session partitioning (`data/ptt_{target_ip}.db`)
- [x] Dynamic "VibeShop" local target lab for challenging E2E tests (`./lab`)
- [ ] Live-fire testing against DVWA/HTB

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only** in controlled lab environments (CTF, HTB, DVWA). Unauthorized use against systems you do not own or have explicit permission to test is **illegal**. The authors are not responsible for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
