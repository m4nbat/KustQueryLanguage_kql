# M365 Phishing - Coronation Lures

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |
| T1566.001 | Spearphishing Attachment | [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |
| T1566.002 | Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |
| T1566.003 | Spearphishing via Service | [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/) |

#### Description
KQL hunt queries to detect phishing emails using coronation-themed lures. These queries identify inbound emails flagged as phishing or malware with coronation-related subjects, including those successfully delivered.

#### Risk
Coronation-themed lures exploit significant public events to trick users into opening malicious attachments or clicking phishing links. Detecting these emails helps identify targeted phishing campaigns exploiting current events.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)

## Defender For Endpoint

```KQL
EmailEvents 
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation"
```

```KQL
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and DeliveryAction !~ "Blocked"
```

```KQL
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and ((DeliveryAction !~ "Blocked" or LatestDeliveryAction !~ "Blocked") or ( DeliveryLocation !~ "Quarantine" or LatestDeliveryLocation !~ "Quarantine" ))
```

```KQL
//visualise emails tagged as malware inbound
EmailEvents
| where TimeGenerated > ago7d)
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation"
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```

```KQL
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and ((DeliveryAction !~ "Blocked" or LatestDeliveryAction !~ "Blocked") or ( DeliveryLocation !~ "Quarantine" or LatestDeliveryLocation !~ "Quarantine" ))
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```
