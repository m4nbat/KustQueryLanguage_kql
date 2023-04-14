# Remote Access Tools 

### Experimental at present as I wrote these on my phone on a train 😁

Catch all detection analytic - datatable needs expanding !!!

let RATs = datatable (name:string)["action1","anydesk","gotoassist","logmein","teamviewer","vnc"];
let RATNames = DeviceFileEvents 
| where PreviousFileName has_any (RATs) or FileName contains has_any (RATs) | distinct FileName;
DeviceNetworkEvents | where InitiatingProcessFileName in~ (RATNames) and ActionType contains "connection"

let RATs = datatable (name:string)["action1","anydesk","gotoassist","logmein","teamviewer","vnc"];
let RATNames = DeviceFileEvents 
| where PreviousFileName has_any (RATs) or FileName contains has_any (RATs) | distinct FileName;
DeviceProcessEvents | where InitiatingProcessFileName in~ (RATNames) or FileName in~ (RATFileNames) or InitiatingProcessParentFileName in~ (RATFileNames)

# Action1 RAT 

**Source:** https://twitter.com/Kostastsale/status/1646256901506605063?t=FL3DWbCPHQQfAZoLTQMt1w&s=19

### Experimental at present as I wrote these on my phone on a train 😁

let action1FileNames = DeviceFileEvents
| where PreviousFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) or FileName in~ (action1FileNames) or InitiatingProcessParentFileName in~ (action1FileNames) 

let action1FileNames = DeviceFileEvents
| where PreviousFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceProcessEvents
| where InitiatingProcessFileName in~ (action1FileNames) and FileName in~ ("PowerShell.exe","cmd.exe") 

let action1FileNames = DeviceFileEvents
| where PreviousFileName contains "action1" or FileName contains "action1" | distinct FileName;
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (action1FileNames) and ActionType in~ ("ConnectionSuccess 

