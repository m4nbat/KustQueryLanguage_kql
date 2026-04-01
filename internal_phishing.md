# Internal Phishing Kusto Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |

#### Description
Queries to detect internal phishing activity where emails are sent within the organisation (intra-org) and are flagged with threat types such as malware or phishing.

#### Risk
Internal phishing campaigns can indicate a compromised internal mailbox being used to spread malware or phishing content to other users within the organisation.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Microsoft - EmailEvents table](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table)

## Defender For Endpoint

```KQL
EmailEvents
| where EmailDirection =~ "Intra-org" and isnotempty(ThreatTypes)
| summarize count() by ThreatTypes
```

```KQL
EmailEvents
| where EmailDirection =~ "Intra-org" and ThreatTypes =~ "malware"
```

```KQL
EmailEvents
| where EmailDirection =~ "Intra-org" and ThreatTypes =~ "phish"
```

```KQL
EmailEvents
| where EmailDirection =~ "Intra-org" and isnotempty(ThreatTypes)
| summarize count() by ThreatTypes
```
