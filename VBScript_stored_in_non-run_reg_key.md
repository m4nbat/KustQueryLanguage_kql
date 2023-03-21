# VBScript stored in non-run CurrentVersion registry key
# Source: Cyborg

`DeviceRegistryEvents
| where RegistryKey has "\\CurrentVersion" 
| where RegistryKey !has "\\Run"
| where RegistryValueData has_any ("RunHTMLApplication","vbscript","jscript","mshtml","mshtml","mshtml ","Execute","CreateObject","RegRead","window.close")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessParentId, DeviceId, ReportId
| order by Timestamp`
