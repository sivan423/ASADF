import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import create_sql_agent

load_dotenv()

os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
os.environ["OPENAI_API_BASE"] = os.getenv("OPENAI_API_BASE", "https://api.deepseek.com")

db = SQLDatabase.from_uri("sqlite:///forensic_evidence.db")
llm = ChatOpenAI(
    model="deepseek-chat",
    temperature=0.0,
    stop=["\nObservation:", "Observation:", "Observation:\n"]
)

agent = create_sql_agent(
    llm=llm, db=db, verbose=True,
    agent_type="zero-shot-react-description",
    max_iterations=10, early_stopping_method="generate",
    agent_executor_kwargs={"handle_parsing_errors": True}
)

query = (
    "Reconstruct a comprehensive forensic timeline of the university data breach incident. "
    "Cross-correlate evidence across all log types. "
    "Every event must cite its Source_Log_ID."
)

print("Running ASADF forensic agent...\n")
try:
    resp = agent.invoke({"input": query})
    print("\n====== FORENSIC REPORT ======\n")
    print(resp["output"])
except Exception as e:
    print(f"Error: {e}")
