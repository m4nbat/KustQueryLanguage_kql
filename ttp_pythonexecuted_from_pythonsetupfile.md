# Execution of Python Scripts via Python Installer Binary

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1202 | Indirect Command Execution | [Indirect Command Execution](https://attack.mitre.org/techniques/T1202/) |
| T1059.006 | Command and Scripting Interpreter: Python | [Python](https://attack.mitre.org/techniques/T1059/006/) |

#### Description
Detects Python scripts being executed by pythonw.exe (the windowless Python interpreter) where the initiating parent process is a setup.exe installer and the command line references a .py file in the AppData directory. This pattern may indicate malware using a bundled Python installer to execute malicious scripts while appearing to be a legitimate software installation.

#### Risk
Threat actors may bundle Python with malicious installers to silently execute scripts from the user's AppData directory, evading detection by masquerading as legitimate software installation activity.

#### Author <Optional>
- **Name:** @kostatsale
- **Github:**
- **Twitter:** https://twitter.com/kostatsale
- **LinkedIn:**
- **Website:**

#### References
- N/A

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessParentFileName has_any "setup.exe" and InitiatingProcessFileName =~ "pythonw.exe" and InitiatingProcessCommandLine has_all (@"\AppData\",".py")
```
