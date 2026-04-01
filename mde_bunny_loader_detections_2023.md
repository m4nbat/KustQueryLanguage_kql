# Bunny Loader MDE Detections

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
Detection analytics for BunnyLoader, a malware-as-a-service (MaaS) loader sold on underground forums. The queries cover command and control activity identified via distinctive user-agent strings and URI patterns, as well as a known registry-based persistence mechanism using a key named "Spyware_Blocker".

#### Risk
BunnyLoader is a capable MaaS loader offering keylogging, credential theft, clipboard hijacking, and remote command execution. Early detection of its C2 communication patterns or persistence mechanism helps prevent full compromise and downstream data theft.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [BunnyLoader - Newest Malware-as-a-Service](https://www.zscaler.com/blogs/security-research/bunnyloader-newest-malware-service)

## Defender For Endpoint

### Command and Control - Useragent and URI related IoCs
```KQL
let UserAgents = datatable(useragent:string)["BunnyLoader","BunnyTasks"];
DeviceNetworkEvents
| extend user_agent = tostring(AdditionalFields.user_agent)
| extend HTTPMethod = tostring(AdditionalFields.method)
| extend uri = tostring(AdditionalFields.uri)
| where ActionType has_any ("HttpConnectionInspected","SslConnectionInspected") and user_agent has_any (UserAgents) and uri has_all ("Bunny") and HTTPMethod =~ "GET"
| extend direction = tostring(AdditionalFields.direction)
| extend host = tostring(AdditionalFields.host)
| extend request_body_len = tostring(AdditionalFields.request_body_len)
| extend response_body_len = tostring(AdditionalFields.response_body_len)
| extend status_code = tostring(AdditionalFields.status_code)
| extend status_msg = tostring(AdditionalFields.status_msg)
| extend tags = tostring(parse_json(tostring(AdditionalFields.tags)))
| extend trans_depth = tostring(AdditionalFields.trans_depth)
| extend version_ = tostring(AdditionalFields.version)
```

### Persistence - Registry key creation
```KQL
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey =~ @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" and RegistryValueName =~ "Spyware_Blocker"
```
