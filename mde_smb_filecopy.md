# Title
Lateral movement copying files to the DC

# Source
@eschlomo

# MITRE ATT&CK
- TA0033 - Lateral Movement
- T1570 - Lateral Tool Transfer
- T1021.002 - SMB/Windows Admin Shares
- T1210 - Exploitation of Remote Services 
- T1021 - Remote Services


MDE queries
```
IdentityDirectoryEvents
| where Timestamp >= ago(1h)
| where ActionType == "SMB file copy"
| extend ParsedFields=parse_json(AdditionalFields)
| extend FileName=tostring(ParsedFields.FileName)
| extend FilePath=tostring(ParsedFields.FilePath)
| extend ActionMethod=tostring(ParsedFields.Method)
| where ActionMethod == "Write"
| summarize Count = count() by Timestamp, ActionType, ActionMethod, AccountDisplayName, DeviceName, DestinationDeviceName, FileName, FilePath
```
