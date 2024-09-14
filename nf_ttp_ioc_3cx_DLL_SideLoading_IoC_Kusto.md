# 3CX Users Under DLL-Sideloading Attack

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1073 | DLL Side-Loading | https://attack.mitre.org/techniques/T1073/
|  T1071 |  Application Layer Protocol  |  https://attack.mitre.org/techniques/T1071/  |

#### Description
Sophos X-Ops is tracking a developing situation concerning a potential supply-chain attack against the 3CX Desktop application, possibly by a nation-state-related group. This threat is notable for its use of DLL sideloading.

The attack involves compromising the 3CXDesktopApp and using it to sideload malicious DLLs onto targeted systems. This page provides an overview of the attack, threat analysis, and queries that can be used for detection in Microsoft Defender for Endpoint (MDE) and Azure Sentinel.

#### Risk
This detection aims to identify and mitigate risks related to supply chain attacks utilizing DLL-sideloading techniques. Attackers may leverage compromised software to gain unauthorized access to sensitive systems or data.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:** 

#### References
- https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
- https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/
- https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv

## Defender For Endpoint
### Combined IOC hunt
```KQL
let urlioc = externaldata(indicator:string, data:string, note:string) 
    [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] 
    with(format="csv",ignoreFirstRecord=true) 
    | where indicator =~ "sha256" 
    | distinct data; 
let sha256ioc = externaldata(indicator:string, data:string, note:string) 
    [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] 
    with(format="csv",ignoreFirstRecord=true) 
    | where indicator =~ "url" 
    | distinct data; 
let iocs = union urlioc, sha256ioc
    | extend iocs = replace_regex(data, @"\[\.\]",".");
DeviceEvents
| where RemoteUrl has_any (iocs) or SHA256 in~ (iocs)
```

### URL IOC hunt
```KQL
let urlioc = externaldata(indicator:string, data:string, note:string) 
    [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] 
    with(format="csv",ignoreFirstRecord=true) 
    | where indicator =~ "url" 
    | extend iocs = replace_regex(data, @"\[\.\]",".") 
    | distinct iocs;
DeviceEvents
| where RemoteUrl has_any (urlioc)
```

### File hash IOC hunt
```KQL
let sha256ioc = externaldata(indicator:string, data:string, note:string) 
    [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] 
    with(format="csv",ignoreFirstRecord=true) 
    | where indicator =~ "sha256" 
    | distinct data;
DeviceFileEvents
| where SHA256 in~ (sha256ioc)
```
### Software hunt
```KQL
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("3CXDesktopApp.exe", "3CX Desktop App")
```

### Software hunt 2
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("3CXDesktopApp.exe","3CXDesktopApp","3CX")
```

