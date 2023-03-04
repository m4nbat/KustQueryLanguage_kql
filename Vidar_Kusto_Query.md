# Vidar Kusto Queries

`// Vidar deployed via fake zoom sites and application. Identify email or phishing containing URLs with known bad domains
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where UrlDomain in~ (domains)`

`// Vidar deployed via fake zoom sites and application
// detect network events where known bad domains and file names downloaded.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
let domains = datatable (domain:string )['zoom-download.host','zoom-download.space','zoom-download.fun','zoomus.host','zoomus.tech','zoomus.website'];
let dowloadUrls = datatable (url:string)[ "https://github[.]com/sgrfbnfhgrhthr/csdvmghfmgfd/raw/main/Zoom.zip"];
let files = datatable (file:string)["zoom.zip"];
DeviceNetworkEvents
| where RemoteUrl has_any (domains) and RemoteUrl has_any (files)`

`// Vidar deployed via fake zoom sites and application
// detect known bad process parent, child relationships
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where (InitiatingProcessParentFileName contains "zoom.exe" or InitiatingProcessFileName contains "zoom.exe") and (InitiatingProcessFileName has_any ("msbuild.exe","decoder.exe") or FileName has_any ("msbuild.exe","decoder.exe","shell.exe"))
| summarize count() by InitiatingProcessParentFileName, InitiatingProcessFileName, FileName`

`//locate users that had interacted with the subdomain in the Vidar stealer log dump
DeviceNetworkEvents
| where RemoteUrl contains "stage.gk.heathrow.com"
| summarize count() by InitiatingProcessAccountName, InitiatingProcessAccountUpn

//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.
//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\System32\\cmd.exe',' /c ','taskkill',' /im ','MSBuild.exe',' /f ',' & ',' timeout ',' /t ',' 6 ',' & ',' del ',' /f ',' /q ')`

`//detects commandline associated with Vidar Cleanup
//Upon successful execution, the malware uses the following commands to uninstall itself from the victim’s device.//https://blog.cyble.com/2022/09/19/new-malware-campaign-targets-zoom-users/
DeviceProcessEvents
| where ProcessCommandLine has_all ('C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe','&','del','C:\\PrograData\\','.dll','&','exit')![image](https://user-images.githubusercontent.com/16122365/222918509-c06869d0-16e8-4053-9e71-1df7cd8e3381.png)`
