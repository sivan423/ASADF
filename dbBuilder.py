import sqlite3
from datetime import datetime

# 连接到你本地的数据库（如果是新建的，会自动创建该文件）
conn = sqlite3.connect("forensic_evidence.db")
cursor = conn.cursor()

# 1. 创建 Windows Event Logs 表 (包含入侵起点、凭据窃取、RDP登录)
cursor.execute('''
CREATE TABLE IF NOT EXISTS evtx_logs (
    Source_Log_ID TEXT PRIMARY KEY,
    timestamp TEXT,
    event_id INTEGER,
    task_category TEXT,
    description TEXT,
    user_account TEXT,
    ip_address TEXT
)
''')

# 2. 创建 Prefetch & Amcache 表 (包含黑客执行 reg.exe 导出 Hive 文件的痕迹)
cursor.execute('''
CREATE TABLE IF NOT EXISTS prefetch_amcache_logs (
    Source_Log_ID TEXT PRIMARY KEY,
    timestamp TEXT,
    program_name TEXT,
    execution_counter INTEGER,
    file_path TEXT,
    sha1_hash TEXT
)
''')

# 3. 创建 ShellBags & LNK 表 (包含黑客用鼠标翻阅文件夹、打开敏感学生数据的 GUI 痕迹)
cursor.execute('''
CREATE TABLE IF NOT EXISTS user_behavior_logs (
    Source_Log_ID TEXT PRIMARY KEY,
    timestamp TEXT,
    artifact_type TEXT, -- ShellBags 或 LNK_File
    accessed_path TEXT,
    target_file TEXT,
    interaction_type TEXT
)
''')

# 4. 创建 数据库审计与网络外发表 (包含黑客最后的批量拖库与流量外发痕迹)
cursor.execute('''
CREATE TABLE IF NOT EXISTS exfiltration_logs (
    Source_Log_ID TEXT PRIMARY KEY,
    timestamp TEXT,
    source_type TEXT, -- SQL_Audit 或 Network_PCAP
    executed_action TEXT,
    data_size_mb REAL,
    destination_ip TEXT
)
''')

conn.commit()
print("取证数据库表结构初始化成功！")

# 模拟黑客攻击痕迹数据
mock_evtx = [
    ('EVTX_001', '2026-05-15 01:30:00', 4625, 'Logon', 'An account failed to log on (Web Server Vulnerability Exploitation).', 'www-data', '185.190.x.x'),
    ('EVTX_002', '2026-05-15 01:45:00', 4688, 'Process Creation', 'Process reg.exe executed with arguments: save hklm\sam sam.hiv', 'SYSTEM', '127.0.0.1'),
    ('EVTX_003', '2026-05-15 01:45:05', 4688, 'Process Creation', 'Process reg.exe executed with arguments: save hklm\system system.hiv', 'SYSTEM', '127.0.0.1'),
    ('EVTX_004', '2026-05-15 02:00:00', 4624, 'Logon', 'An account was successfully logged on via RDP.', 'Administrator', '185.190.x.x')
]

mock_prefetch = [
    ('PF_001', '2026-05-15 01:45:00', 'REG.EXE', 3, 'C:\Windows\System32\reg.exe', 'A4C78B...'),
    ('PF_002', '2026-05-15 02:05:00', 'WINRAR.EXE', 1, 'C:\Program Files\WinRAR\WinRAR.exe', 'F2D91A...')
]

mock_behavior = [
    ('GUI_001', '2026-05-15 02:02:10', 'ShellBags', 'C:\Admin\Student_Privacy_Center\\', '', 'Accessed Directory'),
    ('GUI_002', '2026-05-15 02:03:15', 'LNK_File', 'C:\Admin\Student_Privacy_Center\student_info_2026.xlsx', 'student_info_2026.xlsx', 'Opened File')
]

mock_exfil = [
    ('EXF_001', '2026-05-15 02:04:00', 'SQL_Audit', 'SELECT * FROM Student_Records; (Bulk Export)', 450.0, '127.0.0.1'),
    ('EXF_002', '2026-05-15 02:10:00', 'Network_PCAP', 'Outbound TCP encrypted traffic spikes to malicious external node.', 455.2, '185.190.x.x')
]

# 插入数据
cursor.executemany("INSERT OR IGNORE INTO evtx_logs VALUES (?,?,?,?,?,?,?)", mock_evtx)
cursor.executemany("INSERT OR IGNORE INTO prefetch_amcache_logs VALUES (?,?,?,?,?,?)", mock_prefetch)
cursor.executemany("INSERT OR IGNORE INTO user_behavior_logs VALUES (?,?,?,?,?,?)", mock_behavior)
cursor.executemany("INSERT OR IGNORE INTO exfiltration_logs VALUES (?,?,?,?,?,?)", mock_exfil)

conn.commit()
conn.close()
print("黑客攻击链路证据数据注入成功！")