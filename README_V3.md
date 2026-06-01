# SOC RAG ELITE V3 — Local Cyber Intelligence Platform

> **Agentic RAG Level 4** — Local cybersecurity brain with hybrid search, cross-encoder reranking and specialized agents.

![Version](https://img.shields.io/badge/version-3.0-green)
![Python](https://img.shields.io/badge/python-3.13-blue)
![RAG Level](https://img.shields.io/badge/RAG-Level%204-brightgreen)
![Chunks](https://img.shields.io/badge/chunks-52%2C233-orange)
![Local](https://img.shields.io/badge/100%25-local-success)

---

## What it is

A local SOC/DFIR intelligence system that answers technical cybersecurity questions by retrieving verified information from 52,000+ indexed chunks — MITRE ATT&CK, Sigma rules, CISA KEV, NVD CVEs, Atomic Red Team, Hayabusa, ANSSI and more.

No cloud. No data exfiltration. Everything runs on your machine.

---

## Architecture — RAG Level 4

```
                    QUESTION
                       ↓
              ┌─ QUERY ROUTER ─┐
              │  Auto-detects   │
    ┌─────────┼─────────────────┤
    │         │                 │
  CVE       DFIR          DETECTION  HUNT
  Agent     Agent         Agent      Agent
  cisa+nvd  mitre+atomic  sigma+     mitre+
            +playbook     hayabusa   blogs
    └─────────┴─────────────────┘
                  ↓
         HYBRID SEARCH
         Dense vectors (nomic-embed-text)
              +
         BM25 keyword search
              +
           RRF Fusion
                  ↓
           TOP 60-80 chunks
                  ↓
      CROSS-ENCODER RERANKER
      (ms-marco-MiniLM-L-6-v2)
                  ↓
           TOP 8-15 chunks
                  ↓
      LLM Mistral/Qwen2.5 (local)
                  ↓
       RESPONSE + SOURCES + SCORES
```

---

## Knowledge Base — 52,233 chunks

| Source | Chunks | Update |
|--------|--------|--------|
| Sigma Rules (individual YAML) | 16,692 | 14 days |
| Atomic Red Team | 10,121 | Variable |
| MITRE ATT&CK (709 techniques) | 7,410 | 30 days |
| NVD CVE (critical, 90 days) | 5,694 | 7 days |
| CISA KEV (1,602 entries) | 4,618 | 7 days |
| Hayabusa Rules | 2,211 | Variable |
| Abuse.ch IOC | 1,380 | 1 day |
| DFIR References | 449 | Manual |
| RSS Threat Intel | 188 | 1 day |
| ANSSI Alerts | 93 | Variable |
| Personal Playbooks | 29 | Manual |

---

## Stack

| Component | Technology |
|-----------|-----------|
| Embeddings | nomic-embed-text via Ollama |
| Vector DB | ChromaDB (local, 4.4 GB) |
| LLM | Mistral 7B / Qwen2.5 7B / DeepSeek-R1 7B |
| Reranker | cross-encoder/ms-marco-MiniLM-L-6-v2 |
| Hybrid Search | BM25 (rank-bm25) + RRF Fusion |
| Query Router | Pattern-based agent detection |
| Interface | Python CLI + Interactive menu |

---

## V3 Improvements over V2

| Feature | V2 | V3 |
|---------|----|----|
| Chunk pool | 8 | 60-80 |
| Reranking | ❌ | ✅ cross-encoder |
| Hybrid search | ❌ | ✅ BM25 + vectors |
| Query router | ❌ | ✅ 4 agents |
| Sigma chunks | 2,528 | 16,692 (+560%) |
| Avg distance | 0.68 | 0.55 (-19%) |
| LotL accuracy | ❌ Wrong TTPs | ✅ Correct TTPs |
| Sigma T1053 | 0 results | ✅ 15 rules found |

---

## Installation

```bash
# 1. Clone
git clone https://github.com/Naanasba99/[repo-name]
cd [repo-name]

# 2. Install dependencies
pip3.13 install -r requirements.txt

# 3. Install Ollama models
ollama pull mistral
ollama pull nomic-embed-text

# 4. Build vector database
python3.13 soc_ask_v2.py --rebuild

# 5. Query
python3.13 soc_ask_v2.py --mode blue --question "how to detect pass-the-hash"
```

---

## Usage

```bash
# Interactive menu
python3.13 soc_ask_v2.py

# Direct query with mode
python3.13 soc_ask_v2.py --mode blue   --question "detect pass-the-hash"
python3.13 soc_ask_v2.py --mode red    --question "Windows pivoting techniques"
python3.13 soc_ask_v2.py --mode hunt   --question "hunt Cobalt Strike in logs"
python3.13 soc_ask_v2.py --mode extract --question "Sigma rules for Kerberoasting"

# Theme filtering
python3.13 soc_ask_v2.py --theme mitre --question "T1055 Process Injection"
python3.13 soc_ask_v2.py --theme sigma --question "obfuscated PowerShell detection"
python3.13 soc_ask_v2.py --theme cisa  --question "FortiClient CVEs 2025"

# Increase chunk pool
python3.13 soc_ask_v2.py --topk 20 --question "ransomware techniques"
```

### Modes

| Mode | Use case |
|------|----------|
| `blue` | Defense, detection, incident response, hardening |
| `red` | Offensive techniques, pivoting, persistence |
| `hunt` | Threat hunting, IOC queries |
| `extract` | Sigma rules, Event IDs, exact TTPs |
| `synthesis` | Multi-source synthesis on a topic |
| `checklist` | Generate investigation checklist |

---

## Maintenance

```bash
# Check sources status
python3.13 soc_feed.py --status

# Update all sources
python3.13 soc_feed.py

# Rebuild vector database
python3.13 soc_ask_v2.py --rebuild

# Check reranker dependencies
python3.13 soc_reranker.py

# Sigma re-indexing
python3.13 soc_sigma_fix.py --check
python3.13 soc_sigma_fix.py --extract
```

### Weekly checklist (5 min)

```bash
python3.13 soc_feed.py --status          # Check stale sources
python3.13 soc_feed.py                   # Update if needed
python3.13 soc_ask_v2.py --rebuild       # Rebuild if new data
df -h ~                                   # Check disk space
```

---

## Files

| File | Role |
|------|------|
| `soc_ask_v2.py` | Main RAG engine (v3 patched) |
| `soc_feed.py` | Source fetcher and updater |
| `soc_reranker.py` | Reranker + hybrid search + query router |
| `soc_sigma_fix.py` | Sigma YAML individual indexing |
| `soc.sh` | Real-time SOC monitoring menu |
| `llm_config.py` | LLM configuration |
| `requirements.txt` | Python dependencies |

---

## Requirements

```
Python 3.13
chromadb
langchain-community
langchain-text-splitters
langchain-ollama
sentence-transformers
rank-bm25
tqdm
ollama (local)
```

---

## Data freshness strategy

```
PERMANENT   : MITRE ATT&CK · Sigma · Hayabusa · Atomic Red Team · Playbooks
90 days     : RSS Threat Intel · ANSSI
30 days     : Abuse.ch IOC
7 days      : CISA KEV · NVD CVE
```

---

## Performance benchmarks

| Query type | V2 result | V3 result | Reranker score |
|------------|-----------|-----------|----------------|
| CVE FortiClient 2025 | 9/10 | 9.5/10 | 4.917 |
| Sigma T1053 escalation | 0/10 (no results) | 8.5/10 | 5.038 |
| MITRE LotL T1218 | 3/10 (wrong TTPs) | 8.5/10 | 0.981 |

---

## Roadmap — Level 5

- [ ] Wazuh API integration (live alert enrichment)
- [ ] Velociraptor artifact analysis
- [ ] RAGAS automatic evaluation
- [ ] Cross-session memory
- [ ] KQL/Lucene query generation for Kibana

---

## Legal

All analyses are conducted exclusively from publicly available open-source information.
This system is for defensive security research and educational purposes only.

---

*Built with discipline. Maintained with rigor.*
*SOC RAG Elite — Local Cyber Intelligence Platform*
