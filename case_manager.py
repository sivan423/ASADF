import sqlite3
import os
import hashlib

DB_PATH = "forensic_evidence.db"

TABLE_SCHEMAS = {
    "evtx_logs": {
        "columns": ["Source_Log_ID", "timestamp", "event_id", "task_category", "description", "user_account", "ip_address"],
        "int_cols": ["event_id"]
    },
    "prefetch_amcache_logs": {
        "columns": ["Source_Log_ID", "timestamp", "program_name", "execution_counter", "file_path", "sha1_hash"],
        "int_cols": ["execution_counter"]
    },
    "user_behavior_logs": {
        "columns": ["Source_Log_ID", "timestamp", "artifact_type", "accessed_path", "target_file", "interaction_type"],
        "int_cols": []
    },
    "exfiltration_logs": {
        "columns": ["Source_Log_ID", "timestamp", "source_type", "executed_action", "data_size_mb", "destination_ip"],
        "int_cols": [],
        "float_cols": ["data_size_mb"]
    }
}

def init_database():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS evtx_logs (
        Source_Log_ID TEXT PRIMARY KEY, timestamp TEXT, event_id INTEGER,
        task_category TEXT, description TEXT, user_account TEXT, ip_address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS prefetch_amcache_logs (
        Source_Log_ID TEXT PRIMARY KEY, timestamp TEXT, program_name TEXT,
        execution_counter INTEGER, file_path TEXT, sha1_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_behavior_logs (
        Source_Log_ID TEXT PRIMARY KEY, timestamp TEXT, artifact_type TEXT,
        accessed_path TEXT, target_file TEXT, interaction_type TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS exfiltration_logs (
        Source_Log_ID TEXT PRIMARY KEY, timestamp TEXT, source_type TEXT,
        executed_action TEXT, data_size_mb REAL, destination_ip TEXT)''')
    conn.commit()
    conn.close()

def _convert_row(table_name, record):
    row = []
    for col in TABLE_SCHEMAS[table_name]["columns"]:
        val = record.get(col, "")
        if col in TABLE_SCHEMAS[table_name].get("int_cols", []) and val != "":
            try: val = int(val)
            except (ValueError, TypeError): val = 0
        if col in TABLE_SCHEMAS[table_name].get("float_cols", []) and val != "":
            try: val = float(val)
            except (ValueError, TypeError): val = 0.0
        row.append(val)
    return row

def rebuild_database(case_dict):
    init_database()
    conn = sqlite3.connect(DB_PATH)
    for table in TABLE_SCHEMAS:
        conn.execute(f"DELETE FROM {table}")
    for table_name, records in case_dict.get("evidence", {}).items():
        if table_name not in TABLE_SCHEMAS:
            continue
        cols = TABLE_SCHEMAS[table_name]["columns"]
        ph = ",".join("?" for _ in cols)
        sql = f"INSERT OR IGNORE INTO {table_name} ({','.join(cols)}) VALUES ({ph})"
        for record in records:
            conn.execute(sql, _convert_row(table_name, record))
    conn.commit()
    conn.close()
    kb = case_dict.get("knowledge_base", {})
    if kb.get("mitre_attck"):
        with open("mitre_kb.txt", "w", encoding="utf-8") as f:
            f.write(kb["mitre_attck"])
    if kb.get("sans_for500"):
        with open("sans_kb.txt", "w", encoding="utf-8") as f:
            f.write(kb["sans_for500"])

def get_case_template():
    t = {"case_name": "My Forensic Case", "description": "Describe the incident here", "evidence": {}}
    for name, schema in TABLE_SCHEMAS.items():
        t["evidence"][name] = [{col: "" for col in schema["columns"]}]
    return t

def has_data():
    init_database()
    conn = sqlite3.connect(DB_PATH)
    total = 0
    for table in TABLE_SCHEMAS:
        total += conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    conn.close()
    return total > 0

def preview_database():
    init_database()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    preview = {}
    for table_name in TABLE_SCHEMAS:
        rows = conn.execute(f"SELECT * FROM {table_name} ORDER BY timestamp").fetchall()
        preview[table_name] = [dict(r) for r in rows]
    conn.close()
    return preview

def get_db_hash():
    if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) > 0:
        with open(DB_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    return "DB_NOT_FOUND"
