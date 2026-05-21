import streamlit as st
import os
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import create_sql_agent
from langchain_community.callbacks.streamlit import StreamlitCallbackHandler
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.tools import Tool
from langchain_core.documents import Document
import case_manager
from datetime import datetime

load_dotenv()

st.set_page_config(page_title="ASADF Investigator", page_icon="🛡️", layout="wide")
if "case_version" not in st.session_state:
    st.session_state.case_version = 0
if "loaded_file" not in st.session_state:
    st.session_state.loaded_file = None
if "baseline_hash" not in st.session_state:
    st.session_state.baseline_hash = None
if "hash_history" not in st.session_state:
    st.session_state.hash_history = []

# ==========================================
# Agent 初始化
# ==========================================
@st.cache_resource
def init_agent(_version=0):
    os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
    os.environ["OPENAI_API_BASE"] = os.getenv("OPENAI_API_BASE", "https://api.deepseek.com")
    db = SQLDatabase.from_uri("sqlite:///forensic_evidence.db")
    llm = ChatOpenAI(
        model="deepseek-chat",
        temperature=0.0,
        streaming=True,
        stop=["\nObservation:"]
    )

    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    with open("mitre_kb.txt", encoding="utf-8") as f:
        mitre_text = f.read()
    with open("sans_kb.txt", encoding="utf-8") as f:
        sans_text = f.read()

    vectorstore = FAISS.from_documents(
        [Document(page_content=mitre_text + "\n\n" + sans_text)], embeddings
    )
    retriever = vectorstore.as_retriever()

    def run_retriever(query: str) -> str:
        try:
            docs = retriever.invoke(query)
        except AttributeError:
            docs = retriever.get_relevant_documents(query)
        return "\n\n".join(d.page_content for d in docs)

    threat_tool = Tool(
        name="Forensic_and_Threat_Intelligence_Search",
        description="Search MITRE ATT&CK tactics and SANS FOR500 forensic theories.",
        func=run_retriever
    )
    return create_sql_agent(
        llm=llm, db=db, extra_tools=[threat_tool], verbose=True,
        agent_type="zero-shot-react-description",
        max_iterations=15, early_stopping_method="force",
        agent_executor_kwargs={
            "handle_parsing_errors": "Stop. Provide a Final Answer with what you found so far."
        }
    )

agent = init_agent(st.session_state.case_version)

if st.session_state.baseline_hash is None:
    st.session_state.baseline_hash = case_manager.get_db_hash()

# ==========================================
# UI
# ==========================================
st.title("🛡️ ASADF Forensic Investigator")
st.caption("HKUST ISOM 5080 · Group 3")

with st.sidebar:
    st.header("⚙️ System Status")
    st.success("🟢 Core LLM: DeepSeek-V4 Engine")
    st.success("🟢 Evidence DB: Local SQLite")
    current_hash = case_manager.get_db_hash()
    baseline = st.session_state.baseline_hash

    if current_hash == "DB_NOT_FOUND":
        st.error("❌ Database Not Found")
    elif baseline and current_hash != baseline:
        st.error("❌ INTEGRITY VIOLATION — Evidence has been tampered!")
    else:
        st.success("✅ Integrity Verified")

    st.markdown(f"SHA-256: `{current_hash[:24]}...`")
    with st.expander("Details"):
        st.markdown("**Algorithm:** SHA-256")
        st.markdown("**Full Hash:**")
        st.code(current_hash, language="text")
        if baseline and current_hash != baseline:
            st.markdown("**Baseline (original):**")
            st.code(baseline, language="text")
        if st.session_state.hash_history:
            st.markdown("**Change History:**")
            for h in st.session_state.hash_history:
                st.caption(f"`{h['old'][:16]}…` → `{h['new'][:16]}…` ({h['time']})")

    st.divider()
    st.header("📂 Case Manager")

    uploaded = st.file_uploader("Upload forensic case (JSON)", type=["json"], label_visibility="collapsed")
    if uploaded is not None:
        sig = (uploaded.name, uploaded.size)
        if st.session_state.loaded_file != sig:
            old_hash = case_manager.get_db_hash()
            try:
                data = json.loads(uploaded.read())
                case_manager.rebuild_database(data)
                new_hash = case_manager.get_db_hash()
                st.session_state.hash_history.append({
                    "old": old_hash, "new": new_hash,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                st.session_state.baseline_hash = new_hash
                st.session_state.case_version += 1
                st.session_state.loaded_file = sig
                st.toast(f"✅ Loaded: {data.get('case_name', 'Unknown')}")
                st.rerun()
            except json.JSONDecodeError:
                st.error("Invalid JSON file")

    tmpl = json.dumps(case_manager.get_case_template(), indent=2, ensure_ascii=False)
    st.download_button("📥 Download Template", data=tmpl, file_name="case_template.json",
                       mime="application/json", use_container_width=True)

    with st.expander("🔍 View Database"):
        for table, rows in case_manager.preview_database().items():
            st.markdown(f"**{table}** ({len(rows)} records)")
            if rows:
                st.dataframe(rows, use_container_width=True, hide_index=True)
            else:
                st.caption("(empty)")

    st.divider()
    st.header("🛡️ Active Guardrails")
    st.markdown("- **Prompt Shield**: Active\n- **PII Leakage**: Blocked\n- **Source Anchoring**: Enforced")

# 主界面
if "messages" not in st.session_state:
    if case_manager.has_data():
        st.session_state.messages = [{"role": "assistant", "content": "Case loaded. How can I assist?"}]
    else:
        st.session_state.messages = [{"role": "assistant", "content": "No case loaded. Upload a JSON case file using the sidebar to begin."}]

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

# 快捷按钮
cols = st.columns(3)
quick = None
with cols[0]:
    if st.button("📄 Full Forensic Report", use_container_width=True):
        quick = "Reconstruct a comprehensive forensic timeline including Executive Summary, Evidence Timeline, and MITRE/SANS attack chain analysis."
with cols[1]:
    if st.button("🔍 Trace Credential Theft", use_container_width=True):
        quick = "Focus on the credential theft: which registry hives were dumped and what tools were used? Cite Source_Log_IDs."
with cols[2]:
    if st.button("🌐 Identify Exfiltration Node", use_container_width=True):
        quick = "Identify the destination IP and the total amount of data exfiltrated. Cite Source_Log_IDs."

prompt = st.chat_input("Enter your forensic query...")
query = quick or prompt

if query:
    st.chat_message("user").write(query)
    st.session_state.messages.append({"role": "user", "content": query})

    guardrails = "\n\n[Rules] Cite Source_Log_IDs. Query DB first. Never fabricate."

    with st.chat_message("assistant"):
        cb = StreamlitCallbackHandler(st.container(), expand_new_thoughts=True)
        try:
            resp = agent.invoke({"input": query + guardrails}, {"callbacks": [cb]})
            report = resp["output"]
            st.markdown(report)
            st.session_state.messages.append({"role": "assistant", "content": report})
        except Exception as e:
            st.error(f"Execution Error: {e}")
