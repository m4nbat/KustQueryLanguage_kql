# Internal Phishing Detection (Intra-Org Email Threats)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1534 | Internal Spearphishing | [Internal Spearphishing](https://attack.mitre.org/techniques/T1534/) |

#### Description
Detects phishing and malware emails sent from within the organization (intra-org), which may indicate a compromised account or email infrastructure being used to spread threats internally.

#### Risk
Once an email account is compromised, adversaries use it to send phishing emails internally to bypass external email security controls. Internal phishing campaigns are harder to detect and more likely to succeed.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1534/

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

## Sentinel
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
