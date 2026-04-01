# KQL: Hunting Queries for C2 Using MDE and Network Protection Capability

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |

#### Description
Hunting queries for command-and-control (C2) detection using MDE network protection capabilities. Covers SmartScreen URL warnings for Edge browser, Exploit Guard network protection blocks for third-party browsers, and detection of bypass attempts via user overrides.

#### Risk
Detecting C2 communications via network protection events helps identify compromised devices attempting to connect to malicious infrastructure. Monitoring bypass events is critical to identify users or malware overriding security controls.

#### Author <Optional>
- **Name:**
- **Github:** https://github.com/LearningKijo/KQL
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://github.com/LearningKijo/KQL/blob/main/KQL-Effective-Use/03-kql-MDE-WebProtection.md

## Defender For Endpoint
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUrlWarning"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CustomPolicy"),
MDA_CASB = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) == "CasbPolicy"),
Edge_SS = make_list_if(RemoteUrl, Experience=tostring(ParsedFields.Experience) in ("Malicious", "Phishing")) by DeviceId, DeviceName
| extend MDE_IoC_case = array_length(MDE_IoC)
| extend MDE_WCF_case = array_length(MDE_WCF)
| extend MDA_CASB_case = array_length(MDA_CASB)
| extend Edge_SS_case = array_length(Edge_SS)
| project DeviceId, DeviceName, MDE_IoC_case, MDA_CASB_case, MDE_WCF_case, Edge_SS_case, MDE_IoC, MDE_WCF,  MDA_CASB, Edge_SS
```

**3rd party browser** - Windows Defender Exploit Guard, Network Protection
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ExploitGuardNetworkProtectionBlocked"
| extend ParsedFields=parse_json(AdditionalFields)
| summarize MDE_IoC = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomBlockList"), 
MDE_WCF = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CustomPolicy"),
MDE_NP = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CmdCtrl"),
MDA_CASB = make_list_if(RemoteUrl, ResponseCategory=tostring(ParsedFields.ResponseCategory) == "CasbPolicy") by DeviceId, DeviceName
| extend MDE_IoC_case = array_length(MDE_IoC)
| extend MDE_WCF_case = array_length(MDE_WCF)
| extend MDE_NP_case = array_length(MDE_NP)
| extend MDA_CASB_case = array_length(MDA_CASB)
| project DeviceId, DeviceName, MDE_IoC_case, MDE_NP_case, MDE_WCF_case, MDA_CASB_case,  MDE_IoC, MDE_NP, MDE_WCF,  MDA_CASB
```

**Bypass** - MDE Indicators Warn & MDA Monitored app
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("SmartScreenUserOverride", "NetworkProtectionUserBypassEvent")
| extend Browser = case(
        InitiatingProcessFileName has "msedge", "Edge",
        InitiatingProcessFileName has "chrome", "Chrome", 
        InitiatingProcessFileName has "firefox", "Firefox",
        InitiatingProcessFileName has "opera", "Opera",
"3rd party browser")
| project Timestamp, DeviceId, DeviceName, ActionType, Browser, RemoteUrl
```
