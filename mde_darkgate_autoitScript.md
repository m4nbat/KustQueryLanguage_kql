# DarkGate AutoIT Script Commandline Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.010 | Command and Scripting Interpreter: AutoHotKey & AutoIT | [Command and Scripting Interpreter: AutoHotKey & AutoIT](https://attack.mitre.org/techniques/T1059/010/) |

#### Description
Detects DarkGate malware using AutoIT scripts (.au3) executed via cmd.exe with curl to download and run payloads.

#### Risk
DarkGate may use AutoIT scripts as part of its infection chain to execute malicious code, bypass defenses, and establish persistence. Detection of this activity indicates a potential active DarkGate infection.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- Intrusion Analysis

## Defender For Endpoint
```KQL
DeviceProcessEvents    | where FileName =~ "cmd.exe"   | where ProcessCommandLine has_all ("curl","http",".au3")
```
