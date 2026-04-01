# File Downloads

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |

#### Description
Detects file downloads of potentially malicious file types (DLL, EXE, ZIP, 7z, PS1, PS, BAT, SH) via HTTP connections inspected by MDE.

#### Risk
Downloads of executable file types such as DLLs, executables, scripts, and archives via HTTP may indicate malware delivery, tool staging, or lateral movement activities.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
-

## Defender For Endpoint
```KQL
// Detect file downloads
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction= tostring(json.direction), user_agent=tostring(json.user_agent), uri=tostring(json.uri)
| where uri matches regex @"\.(?:dll|exe|zip|7z|ps1|ps|bat|sh)$"
```
