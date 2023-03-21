# VBScript stored in non-run CurrentVersion registry key
# Source: Cyborg www.cyborgsecurity.io

`DeviceRegistryEvents
| where RegistryKey has "\\CurrentVersion" 
| where RegistryKey !has "\\Run"
| where RegistryValueData has_any ("RunHTMLApplication","vbscript","jscript","mshtml","mshtml","mshtml ","Execute","CreateObject","RegRead","window.close")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessParentId, DeviceId, ReportId
| order by Timestamp`

`SecurityEvent
| where ObjectName has "\\CurrentVersion"
| where ObjectName !has "\\Run"
| where NewValue has_any ("RunHTMLApplication","vbscript","jscript","mshtml","mshtml","mshtml ","Execute","CreateObject","RegRead","window.close")
| project TimeGenerated, Computer, Process, ObjectName, ObjectValueName, NewValue, OldValue, SubjectUserName, NewProcessId, SourceComputerId
| order by TimeGenerated`
