kb_content = """
MITRE ATT&CK Threat Intelligence Knowledge Base:

1. Credential Dumping (T1003): 
Malicious actors may attempt to extract credential material from the Security Account Manager (SAM) database. 
Command Line Indicator: Execution of 'reg.exe save hklm\sam' or 'reg.exe save hklm\system'. 
Forensic Significance: This allows offline cracking of local account hashes (like Administrator), leading to Privilege Escalation and Lateral Movement.

2. Exploitation for Client Execution (T1203):
Indicator: Failed or suspicious logons from the 'www-data' account.
Forensic Significance: 'www-data' is a low-privileged web server account. Suspicious activity here strongly indicates a Web Vulnerability Exploitation (Initial Access).

3. Data Staged (T1074) and Automated Exfiltration (T1020):
Indicator: Execution of compression tools like 'WINRAR.EXE' followed by large outbound network spikes.
Forensic Significance: Attackers compress stolen data (like SQL exports) to evade DLP (Data Loss Prevention) and reduce transfer time before exfiltration.
"""

with open("mitre_kb.txt", "w", encoding="utf-8") as f:
    f.write(kb_content)

print("MITRE 知识库 mitre_kb.txt 生成成功！")