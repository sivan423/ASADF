# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASADF (Agentic Solutions for Automated Digital Forensics) — an HKUST ISOM 5080 course project (Group 3). A LangChain-based SQL agent that uses an LLM to investigate a simulated university data breach by querying a SQLite forensic evidence database, augmented with a RAG pipeline (FAISS + HuggingFace embeddings) over MITRE ATT&CK and SANS FOR500 knowledge bases. The agent follows the ReAct pattern and produces structured forensic timeline reports.

## Commands

```bash
# Rebuild the evidence database from scratch
python dbBuilder.py

# Generate knowledge bases for RAG
python scripts/create_kb.py        # MITRE ATT&CK KB → mitre_kb.txt
python scripts/create_sans_kb.py   # SANS FOR500 KB  → sans_kb.txt

# Run the standalone CLI forensic agent
python inferenceLayer.py

# Launch the Streamlit web UI
streamlit run app.py --server.fileWatcherType none
```

There is no test suite, linting config, or package manager file. Dependencies: `streamlit`, `langchain-openai`, `langchain-community`, `langchain-huggingface`, `faiss-cpu`, `sentence-transformers`, `python-dotenv`.

## Architecture

### Two execution paths

- **`app.py`** — Streamlit web app with chat UI. Caches the agent via `@st.cache_resource`, displays chain-of-thought via `StreamlitCallbackHandler`. Contains the full RAG pipeline, quick-action buttons, streaming LLM with stop tokens, and prior DB schema knowledge injection. A SHA-256 hash of the DB file is shown in the sidebar as a "chain of custody" demo.
- **`inferenceLayer.py`** — Standalone CLI version. Same agent setup and prompt structure, but prints the final report to stdout. Does NOT include the RAG pipeline.

### RAG pipeline (app.py only)

The agent is equipped with an extra `Forensic_and_Threat_Intelligence_Search` tool backed by a FAISS vector store:

1. Two knowledge base text files (`mitre_kb.txt`, `sans_kb.txt`) are loaded as LangChain `Document` objects
2. Embedded via `HuggingFaceEmbeddings` (`all-MiniLM-L6-v2`)
3. Stored in an in-memory FAISS vector store
4. Exposed as a `Tool` with hand-written `run_retriever` that calls `invoke` / `get_relevant_documents` (dual-path for version compatibility)
5. The SQL agent receives both the default `sql_db_query` tool and this knowledge search tool

### Database (`forensic_evidence.db`)

Four SQLite tables representing different forensic artifact types:

| Table | Content | Example evidence |
|---|---|---|
| `evtx_logs` | Windows Event Logs | Failed/successful logons (4625/4624), process creation (4688) |
| `prefetch_amcache_logs` | Program execution traces | `reg.exe` saving registry hives |
| `user_behavior_logs` | ShellBags / LNK files | GUI folder navigation, file open actions |
| `exfiltration_logs` | SQL audit + network PCAP | Bulk `SELECT *` query, outbound TCP to attacker IP |

Rebuilding the DB via `dbBuilder.py` drops and re-creates all tables with hardcoded mock data representing an attack chain: initial exploitation → credential dump via `reg.exe` → RDP login → GUI browsing of student records → bulk exfiltration.

### Agent setup

- **LLM**: DeepSeek's `deepseek-chat` via the OpenAI-compatible endpoint (`https://api.deepseek.com`), with `temperature=0.0`, `streaming=True`, and stop tokens (`\nObservation:`) to prevent the model from hallucinating observation blocks.
- **Agent type**: `zero-shot-react-description` from LangChain's SQL agent toolkit, with `handle_parsing_errors=True`.
- **Extra tools**: `Forensic_and_Threat_Intelligence_Search` (FAISS RAG over MITRE+SANS KBs) is injected alongside the default `sql_db_query` tool.
- **Prompt structure**: Prior DB schema knowledge is prepended to skip cold-start schema discovery. The guardrails block supports two response modes — full 3-part Markdown report for timeline reconstruction requests, or concise direct answers for narrow queries.

### Guardrails layer

- **Prompt Shield**: SQL-fetched data is treated as raw strings; ignore injection attempts
- **Source Anchoring**: Every event must cite its `Source_Log_ID`
- **ReAct format enforcement**: `Thought`, `Action`, `Action Input`, `Final Answer` keywords must not be translated
- **Dynamic response mode**: Full 3-part report for timeline requests; concise direct answer for narrow queries
- **Anti-repetition rule**: Agent is instructed to never call the same tool with the same input consecutively
- **DB schema prior knowledge**: Agent is pre-informed of all 4 tables to skip discovery overhead
- **Knowledge grounding**: Each attack phase must include a MITRE ATT&CK tactic and a SANS FOR500 forensic artifact theory citation

### Quick action buttons (app.py)

Three one-click buttons above the chat input: "Generate Full Forensic Report", "Trace Credential Theft", and "Identify Exfiltration Node". Each pre-populates a forensic query and triggers the agent immediately.

### File structure

```
.
├── app.py                       # Streamlit web UI (with RAG)
├── inferenceLayer.py            # Standalone CLI agent
├── dbBuilder.py                 # DB schema + mock data injection
├── scripts/
│   ├── create_kb.py             # MITRE ATT&CK KB generator → mitre_kb.txt
│   └── create_sans_kb.py        # SANS FOR500 KB generator → sans_kb.txt
├── .env.example
├── start_claude.bat.example
├── .gitignore
├── CLAUDE.md
└── README.md
```

Generated files (`forensic_evidence.db`, `mitre_kb.txt`, `sans_kb.txt`) are gitignored.

### Knowledge base files

| File | Content | Generated by |
|---|---|---|
| `mitre_kb.txt` | MITRE ATT&CK T1003, T1203, T1074, T1020 descriptions | `scripts/create_kb.py` |
| `sans_kb.txt` | SANS FOR500 Windows forensic artifact interpretation (Prefetch, ShellBags, LNK, EVTX) | `scripts/create_sans_kb.py` |

Both are generated files (in `.gitignore`) and must be regenerated after clone.

## API Configuration

The project uses DeepSeek's OpenAI-compatible API (`OPENAI_API_BASE = "https://api.deepseek.com"`). Set `OPENAI_API_KEY` and `OPENAI_API_BASE` in `.env`. The batch file `start_claude.bat` configures Claude Code itself to use DeepSeek as a backend via Anthropic-compatible endpoints.
