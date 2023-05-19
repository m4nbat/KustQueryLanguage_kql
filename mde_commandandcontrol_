# KQL : Hunting queries for C2 using MDE and network protection capability

# Source: 
- https://github.com/LearningKijo/KQL/blob/main/KQL-Effective-Use/03-kql-MDE-WebProtection.md

**Edge browser** - Microsoft SmartScreen
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
