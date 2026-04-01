# Detect Use of RClone to Compress and Exfiltrate Data

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/) |
| T1020 | Automated Exfiltration | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) |

#### Description
Detects the execution of RClone, a command-line tool used to sync files to cloud storage providers. Threat actors abuse RClone to exfiltrate sensitive data to attacker-controlled cloud storage accounts during ransomware and data theft operations.

#### Risk
RClone is a legitimate tool frequently abused by ransomware operators and threat actors for bulk data exfiltration. Detection of RClone process activity with data transfer arguments may indicate an active data theft operation.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- N/A

## Defender For Endpoint
```KQL
let Rclone_Commands = dynamic(["pass","user","copy","mega","sync","config","lsd","remote","ls"]);
    DeviceProcessEvents
    | where FileName contains "rclone"
    | where ProcessCommandLine has_any (Rclone_Commands)
```
