# Vidar Stealer Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.002 | User Execution: Malicious File | [Malicious File](https://attack.mitre.org/techniques/T1204/002/) |

#### Description
Detection queries for Vidar information stealer deployed via fake Zoom sites. Identifies network connections to Vidar C2 infrastructure and suspicious process relationships.

#### Risk
Vidar stealer harvests credentials and cryptocurrency wallets. It was deployed through fake Zoom installer sites targeting users who searched for Zoom downloads.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/

## Defender For Endpoint
```KQL
// Vidar deployed via fake zoom sites and application. Identify email or phishing containing URLs with known bad domains
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where UrlDomain in~ (domains)
```

```KQL
// Vidar deployed via fake zoom sites and application
// detect network events where known bad domains and file names downloaded.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
DeviceNetworkEvents
| where RemoteUrl has_any (domains) and RemoteUrl has_any (files)
```

```KQL
// Vidar deployed via fake zoom sites and application
// detect known bad process parent, child relationships
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where (InitiatingProcessParentFileName contains "zoom.exe" or InitiatingProcessFileName contains "zoom.exe") and (InitiatingProcessFileName has_any ("msbuild.exe","decoder.exe") or FileName has_any ("msbuild.exe","decoder.exe","shell.exe"))
| summarize count() by InitiatingProcessParentFileName, InitiatingProcessFileName, FileName
```

```KQL
//locate users that had interacted with the subdomain in the Vidar stealer log dump
DeviceNetworkEvents
| where RemoteUrl contains "stage.gk.heathrow.com"
| summarize count() by InitiatingProcessAccountName, InitiatingProcessAccountUpn
```

```KQL
//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\System32\\cmd.exe',' /c ','taskkill',' /im ','MSBuild.exe',' /f ',' & ',' timeout ',' /t ',' 6 ',' & ',' del ',' /f ',' /q ')
```

```KQL
//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe','&','del','C:\\PrograData\\','.dll','&','exit')![image](https://user-images.githubusercontent.com/16122365/222918509-c06869d0-16e8-4053-9e71-1df7cd8e3381.png)
```

## Sentinel
```KQL
// Vidar deployed via fake zoom sites and application. Identify email or phishing containing URLs with known bad domains
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where UrlDomain in~ (domains)
```

```KQL
// Vidar deployed via fake zoom sites and application
// detect network events where known bad domains and file names downloaded.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
DeviceNetworkEvents
| where RemoteUrl has_any (domains) and RemoteUrl has_any (files)
```

```KQL
// Vidar deployed via fake zoom sites and application
// detect known bad process parent, child relationships
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where (InitiatingProcessParentFileName contains "zoom.exe" or InitiatingProcessFileName contains "zoom.exe") and (InitiatingProcessFileName has_any ("msbuild.exe","decoder.exe") or FileName has_any ("msbuild.exe","decoder.exe","shell.exe"))
| summarize count() by InitiatingProcessParentFileName, InitiatingProcessFileName, FileName
```

```KQL
//locate users that had interacted with the subdomain in the Vidar stealer log dump
DeviceNetworkEvents
| where RemoteUrl contains "stage.gk.heathrow.com"
| summarize count() by InitiatingProcessAccountName, InitiatingProcessAccountUpn
```

```KQL
//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\System32\\cmd.exe',' /c ','taskkill',' /im ','MSBuild.exe',' /f ',' & ',' timeout ',' /t ',' 6 ',' & ',' del ',' /f ',' /q ')
```

```KQL
//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe','&','del','C:\\PrograData\\','.dll','&','exit')![image](https://user-images.githubusercontent.com/16122365/222918509-c06869d0-16e8-4053-9e71-1df7cd8e3381.png)
```
