# Lateral Movement - Copying Files to the DC

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1570 | Lateral Tool Transfer | [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/) |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| T1210 | Exploitation of Remote Services | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| T1021 | Remote Services | [Remote Services](https://attack.mitre.org/techniques/T1021/) |

#### Description
Detects file copy operations to a Domain Controller (DC) over SMB using IdentityDirectoryEvents. The query identifies write operations performed via SMB file copy, which may indicate lateral movement or pre-ransomware staging activity targeting the DC.

#### Risk
Copying files to a Domain Controller via SMB administrative shares is a strong indicator of lateral movement or ransomware staging. Attackers use this technique to deploy tools, backdoors, or ransomware payloads across the domain by leveraging compromised credentials and admin share access.

#### Author <Optional>
- **Name:** eschlomo
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References

## Defender For Endpoint
```KQL
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
