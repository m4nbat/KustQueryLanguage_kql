# Data Exfiltration to AWS S3 via Commandline

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1537 | Transfer Data to Cloud Account | [Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |

#### Description
Detects potential data exfiltration to AWS S3 using the AWS CLI tool launched from WaAppAgent.exe (Azure Windows Agent), excluding DLL and EXE files. This pattern may indicate an attacker using a compromised Azure agent to exfiltrate data to attacker-controlled cloud storage.

#### Risk
Adversaries may use the AWS CLI to transfer data to attacker-controlled S3 buckets. Exfiltration via WaAppAgent.exe could indicate abuse of Azure infrastructure for data theft, bypassing traditional exfiltration detection.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- DFIR Report

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName endswith "WaAppAgent.exe" and InitiatingProcessCommandLine has_all (" s3 "," cp ","--exclude",".dll",".exe")
```
