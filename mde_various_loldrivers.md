# LOLDRIVERS Threat Hunting

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1014 | Rootkit | [Rootkit](https://attack.mitre.org/techniques/T1014/) |
| T1068 | Exploitation for Privilege Escalation | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) |

#### Description
Hunt for known vulnerable or malicious drivers using the loldrivers.io dataset. The query pulls the live driver database from loldrivers.io and cross-references file hashes (SHA1, MD5, SHA256) observed in DeviceFileEvents against known vulnerable samples to identify BYOVD (Bring Your Own Vulnerable Driver) attacks.

#### Risk
Known vulnerable drivers (LOLDrivers) are abused by threat actors and ransomware groups to disable security products, escalate privileges, or load unsigned code. Detecting these drivers early can prevent complete host compromise and defence evasion.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [LOLDRIVERS](https://www.loldrivers.io)

## Defender For Endpoint
```KQL
let loldrivers = externaldata(Id:string, Author:string, Created:datetime, MitreID:string, Category:string, Verified:bool, Commands:dynamic, Resources:dynamic, Acknowledgement:dynamic, Detection:dynamic, KnownVulnerableSamples:dynamic, Tags:dynamic)
[h@'https://www.loldrivers.io/api/drivers.json']
with(format='multijson')
| mv-expand KnownVulnerableSamples
| extend SHA256_ = tostring(KnownVulnerableSamples.SHA256)
| extend SHA1_ = tostring(KnownVulnerableSamples.SHA1)
| extend MD5_ = tostring(KnownVulnerableSamples.MD5)
;
DeviceFileEvents
| where SHA1 in~ (loldrivers) or MD5 in~ (loldrivers) or SHA256 in~ (loldrivers)
```
