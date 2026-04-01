# Zip Domain Hunt Query

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects network connections to .zip top-level domains, which have been abused by threat actors for phishing campaigns due to their resemblance to archive file names.

#### Risk
Connections to .zip domains may indicate phishing activity or malware downloads, as threat actors exploit the .zip TLD to confuse users and security tools by mimicking archive file names.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
-

## Defender For Endpoint
```KQL
DeviceNetworksEvents
| where RemoteUrl matches regex @"(?i)^(?:https?://)?[^/]+\.zip$"
```