# Tactic: Initial Access

# Techniques

|ID|Technique|Detail|
|--|--|--|
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| T1566.001 | 	Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |
| T1566.002 | Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |
| T1566.003 | Spearphishing via Service | https://attack.mitre.org/techniques/T1566/003/ |

# KQL hunt queries:
Find all intrusion attempts for analysis:

```
EmailEvents 
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation"
```

Find successful attempts:

```
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and DeliveryAction !~ "Blocked"
```

There is actually a bit more nuance to the EmailEvents table when post delivery actions may have been taken to quarrantine or block eg ZAP:

```
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and ((DeliveryAction !~ "Blocked" or LatestDeliveryAction !~ "Blocked") or ( DeliveryLocation !~ "Quarantine" or LatestDeliveryLocation !~ "Quarantine" ))
```

Viualising the data for the above:

```
//visualise emails tagged as malware inbound
EmailEvents
| where TimeGenerated > ago7d)
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation"
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```

```
EmailEvents
| where EmailDirection =~ "Inbound" and ThreatTypes has_any ("Phish","Malware") and Subject contains "coronation" and ((DeliveryAction !~ "Blocked" or LatestDeliveryAction !~ "Blocked") or ( DeliveryLocation !~ "Quarantine" or LatestDeliveryLocation !~ "Quarantine" ))
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```
