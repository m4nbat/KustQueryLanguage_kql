# M365 Coronation-Lure Phishing Campaign Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |
| T1566.002 | Phishing: Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detection queries for phishing campaigns using coronation-themed lures. Identifies inbound phishing and malware emails with coronation-related subjects, including bypassed deliveries.

#### Risk
Threat actors commonly exploit major world events (like royal coronations) as phishing lures. These campaigns can bypass email security when legitimate brands or events are impersonated.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1566/

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

## Sentinel
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
