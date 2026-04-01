# LolBin: Winlogon Suspicious Network Connection (Possible Injection)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1055 | Process Injection | [Process Injection](https://attack.mitre.org/techniques/T1055/) |
| T1078 | Valid Accounts | [Valid Accounts](https://attack.mitre.org/techniques/T1078/) |

#### Description
Detects winlogon.exe processes that create remote threads (indicative of process injection) and have outbound public network connections. Winlogon is not expected to make external network connections under normal circumstances.

#### Risk
Adversaries inject into winlogon.exe to gain SYSTEM-level privileges and evade detection. Outbound connections from winlogon.exe strongly indicate compromise or malicious code injection.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://twitter.com/ellishlomo/status/1652312221156794369
- https://attack.mitre.org/techniques/T1055/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where FileName == "winlogon.exe"
| where ActionType == "CreateRemoteThread"
| join (
DeviceNetworkEvents
| where RemoteIPType == "Public"
) on DeviceId
```

## Sentinel
```KQL
DeviceProcessEvents
| where FileName == "winlogon.exe"
| where ActionType == "CreateRemoteThread"
| join (
DeviceNetworkEvents
| where RemoteIPType == "Public"
) on DeviceId
```
