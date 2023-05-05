
```
//visualise emails tagged as malware inbound
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection =~ "Inbound"
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```


```
//internal to internal, or outbound email with a malware detection
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection !~ "Inbound" and SenderFromAddress !~ "postmaster@heathrow.com" and AttachmentCount > 0
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```
