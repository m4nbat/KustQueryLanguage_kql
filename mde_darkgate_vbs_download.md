# DarkGate VBS File Download

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | [Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/) |

#### Description
Detects DarkGate malware using VBS scripts executed via wscript.exe to make network connections on port 2351, which is associated with DarkGate C2 communications.

#### Risk
DarkGate uses VBS files to download additional payloads and communicate with its command and control infrastructure. Detection indicates a potential active DarkGate infection leveraging Visual Basic scripts.

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
DeviceNetworkEvents
| where InitiatingProcessCommandLine has_all (".vbs") and RemotePort == 2351 and InitiatingProcessFileName =~ "wscript.exe"
```
