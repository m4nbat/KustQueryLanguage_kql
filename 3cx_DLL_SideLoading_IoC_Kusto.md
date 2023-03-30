# 3CX users under DLL-sideloading attack

Sophos X-Ops is tracking a developing situation concerning a seeming supply-chain attack against the 3CX Desktop application, possibly undertaken by a nation-state-related group. This page provides an overview of the situation, a threat analysis, information for hunters, and information on detection protection.

## Sources:
- https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
- https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/


`let urlioc = externaldata(indicator:string, data:string, note:string) [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] with(format="csv",ignoreFirstRecord=true) | where indicator =~ "sha256" | distinct data; 
let sha256ioc = externaldata(indicator:string, data:string, note:string) [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] with(format="csv",ignoreFirstRecord=true) | where indicator =~ "url" | distinct data; 
let iocs = union urlioc, sha256ioc
| extend iocs = replace_regex(data, @"\[\.\]",".");
DeviceEvents
| where RemoteUrl has_any (iocs) or SHA256 in~ (iocs)`

`let urlioc = externaldata(indicator:string, data:string, note:string) [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] with(format="csv",ignoreFirstRecord=true) | where indicator =~ "url" | extend iocs = replace_regex(data, @"\[\.\]",".") | distinct iocs; 
DeviceEvents
| where RemoteUrl has_any (urlioc)`

`let sha256ioc = externaldata(indicator:string, data:string, note:string) [h@"https://raw.githubusercontent.com/sophoslabs/IoCs/master/3CX%20IoCs%202023-03.csv"] with(format="csv",ignoreFirstRecord=true) | where indicator =~ "sha256" | distinct data; 
DeviceFileEvents
| where SHA256 in~ (sha256ioc)`

`DeviceTvmSoftwareInventory
| where SoftwareName has_any ("3CXDesktopApp.exe", "3CX Desktop App")`
