sans_content = """
SANS FOR500 Windows Forensic Analysis Knowledge Base:

1. Evidence of Application Execution (应用程序执行证据):
- Artifacts: Prefetch, Amcache.hve, Shimcache.
- Forensic Interpretation: These artifacts prove that a specific executable (e.g., reg.exe, winrar.exe, sqlcmd.exe) was run on the system. They provide execution timestamps, run counts, and file paths.

2. Evidence of File and Folder Opening (文件与文件夹访问证据):
- Artifacts: Shortcut (LNK) Files, ShellBags.
- Forensic Interpretation: 
  * LNK files prove that a user opened a specific file (e.g., student_info_2026.xlsx) or application.
  * ShellBags prove that a user navigated to a specific directory (e.g., C:\\Admin\\Student_Privacy_Center\\) using the Windows GUI (Windows Explorer). This strongly indicates interactive, human-driven lateral movement and data discovery.

3. Evidence of Account Usage & Authentication (账户使用与认证证据):
- Artifacts: Windows Event Logs (Security Log).
- Forensic Interpretation: Event ID 4624 (Successful Logon) and 4625 (Failed Logon) track account access. Event ID 4688 (Process Creation) tracks command-line executions (e.g., executing registry dumps).
"""

with open("sans_kb.txt", "w", encoding="utf-8") as f:
    f.write(sans_content)

print("[OK] SANS FOR500 取证知识库 sans_kb.txt 生成成功！")