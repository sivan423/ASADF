# ASADF — Agentic Solutions for Automated Digital Forensics

HKUST ISOM 5080 · Group 3

An LLM-powered forensic investigation agent that reconstructs data breach timelines by querying a SQLite evidence database, augmented with a RAG pipeline over MITRE ATT&CK and SANS FOR500 knowledge bases. Built with LangChain, FAISS, and DeepSeek.

## Architecture

```
User Query ("Reconstruct the breach timeline...")
        │
        ▼
┌──────────────────────────────────────┐
│  Prompt Shield + ReAct Guardrails    │
│  (Thought → Action → Action Input)   │
│  + DB Schema Prior Knowledge         │
│  + Anti-Repetition Rule              │
└──────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────┐
│  LangChain SQL Agent (DeepSeek)      │
│  zero-shot-react-description         │
│                                      │
│  Tools:                              │
│  ├── sql_db_query (evidence DB)      │
│  └── Forensic_Threat_Intel_Search    │
│      (RAG over MITRE + SANS KBs)     │
└──────────────────────────────────────┘
        │                        │
        ▼                        ▼
┌──────────────────┐   ┌────────────────────────┐
│  SQLite Evidence │   │  FAISS Vector Store     │
│  DB (4 tables)   │   │  MITRE ATT&CK +         │
│                  │   │  SANS FOR500 KBs        │
└──────────────────┘   └────────────────────────┘
        │                        │
        ▼                        ▼
┌──────────────────────────────────────┐
│  Structured Forensic Report          │
│  Executive Summary → Timeline →      │
│  4-Phase Attack Chain Analysis      │
│  (with MITRE T-codes + SANS theory) │
└──────────────────────────────────────┘

  〔Sidebar〕🔐 SHA-256 Integrity Check — Baseline comparison · Tamper detection · Change history
```

## Simulated Attack Scenario

The mock evidence traces a complete kill chain:

| Phase | Action | Evidence Source |
|---|---|---|
| Initial Access | Web server exploitation via `www-data` account | `evtx_logs` (Event 4625) |
| Credential Access | SAM/SYSTEM hive dump via `reg.exe save` | `evtx_logs` (Event 4688), `prefetch_amcache_logs` |
| Lateral Movement | RDP login as Administrator | `evtx_logs` (Event 4624) |
| Discovery | GUI browsing of `Student_Privacy_Center` folder | `user_behavior_logs` (ShellBags, LNK) |
| Collection | `SELECT * FROM Student_Records` bulk export (450 MB) | `exfiltration_logs` (SQL_Audit) |
| Exfiltration | Encrypted TCP spike to attacker IP (455 MB) | `exfiltration_logs` (Network_PCAP) |

## Database Schema

Four SQLite tables model distinct forensic artifact categories:

| Table | Artifact Type | Key Fields |
|---|---|---|
| `evtx_logs` | Windows Event Logs | `event_id`, `task_category`, `user_account`, `ip_address` |
| `prefetch_amcache_logs` | Program Execution Traces | `program_name`, `execution_counter`, `sha1_hash` |
| `user_behavior_logs` | ShellBags & LNK Files | `artifact_type`, `accessed_path`, `target_file` |
| `exfiltration_logs` | SQL Audit & Network PCAP | `source_type`, `data_size_mb`, `destination_ip` |

Every record has a `Source_Log_ID` primary key used for evidence anchoring in the final report. Schema details → `dbBuilder.py`.

## Setup

```bash
# 1. Clone
git clone https://github.com/sunstriderLHT/ASADF.git
cd ASADF

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API key
cp .env.example .env
# Edit .env, replace with your DeepSeek API key:
#   OPENAI_API_KEY=sk-your-key-here
#   OPENAI_API_BASE=https://api.deepseek.com

# 4. Build the evidence database
python dbBuilder.py

# 5. Generate the knowledge bases for RAG
python scripts/create_kb.py        # MITRE ATT&CK KB → mitre_kb.txt
python scripts/create_sans_kb.py   # SANS FOR500 KB  → sans_kb.txt
```


## Usage

```bash
# Streamlit web UI
streamlit run app.py --server.fileWatcherType none
```

### Web UI Features

- **Quick Investigation Actions** — one-click buttons for common forensic queries: full timeline report, credential theft tracing, exfiltration node identification
- **Chat interface** for free-form forensic questioning
- **Real-time chain-of-thought** — the agent's reasoning steps (Thought → Action → Action Input) stream live in the UI
- **RAG-augmented reasoning** — the agent can query a FAISS vector store combining MITRE ATT&CK and SANS FOR500 knowledge to ground its analysis in established forensic theory
- **Dynamic response format** — the agent adapts its output: comprehensive 3-part report for timeline reconstruction requests, concise direct answers for narrow questions
- **🔐 Evidence Integrity Check** — sidebar panel displays the evidence database's SHA-256 hash with tamper detection: stores a baseline hash on first load, continuously compares it against the current file, and shows a clear ✅ Integrity Verified or ❌ INTEGRITY VIOLATION status. Uploading a new case file automatically logs the hash transition with timestamps in the change history (expandable Details section).

## Guardrails

- **Prompt Shield**: SQL-fetched data is treated as raw strings; injection attempts like "Ignore previous rules" are blocked at the prompt level
- **Source Anchoring**: every event in the final report must cite its `Source_Log_ID`
- **ReAct Format Lock**: the `Thought` / `Action` / `Action Input` / `Final Answer` keywords are enforced to prevent parser failures
- **Knowledge-Grounded Analysis**: reports must cite MITRE ATT&CK T-codes and SANS FOR500 forensic theory for each attack phase
- **Anti-Repetition Rule**: the agent is instructed to never call the same tool with the same input consecutively, preventing infinite loops
- **DB Schema Prior Knowledge**: the agent receives the database architecture upfront to skip cold-start schema discovery

## Knowledge Bases

The RAG pipeline uses two complementary knowledge sources:

| KB | Content | Generator |
|---|---|---|
| MITRE ATT&CK | T1003 Credential Dumping, T1203 Exploitation, T1074 Data Staged, T1020 Automated Exfiltration | `scripts/create_kb.py` |
| SANS FOR500 | Windows forensic artifact interpretation — Prefetch/Amcache (execution evidence), ShellBags/LNK (file/folder access), EVTX (authentication) | `scripts/create_sans_kb.py` |

### MITRE ATT&CK Mappings

| Technique | ID | Evidence |
|---|---|---|
| Credential Dumping | T1003 | `reg.exe save hklm\sam` / `hklm\system` |
| Exploitation for Client Execution | T1203 | Suspicious `www-data` logon failures |
| Data Staged | T1074 | `WINRAR.EXE` execution before exfiltration |
| Automated Exfiltration | T1020 | Bulk SQL export + encrypted TCP spike |

## File Structure

```
.
├── app.py                       # Streamlit web UI (with RAG pipeline)
├── case_manager.py              # Database operations + integrity hash management
├── inferenceLayer.py            # Standalone CLI agent
├── dbBuilder.py                 # Database schema + mock data injection
├── scripts/
│   ├── create_kb.py             # MITRE ATT&CK knowledge base generator
│   └── create_sans_kb.py        # SANS FOR500 knowledge base generator
├── .env.example                 # API key configuration template
├── .gitignore
├── CLAUDE.md
├── forensic_evidence.db         # SQLite evidence database (generated)
├── mitre_kb.txt                 # MITRE knowledge base (generated)
├── README.md
├── requirements.txt             # Python dependencies
├── sample_case_insider.json     # Sample case: insider data theft
├── sample_case_phishing.json    # Sample case: phishing attack
├── sans_kb.txt                  # SANS knowledge base (generated)
└── start_claude.bat.example
```
