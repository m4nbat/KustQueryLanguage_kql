# M365 Email Threat Hunting Rules

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |

#### Description
Email threat hunting queries for Microsoft 365. Visualizes inbound malware detections and identifies potential internal threat activity through non-inbound email with malware detections.

#### Risk
Email-based threats remain the primary initial access vector. These queries help identify patterns in malware delivery and potential compromised accounts sending malicious emails internally.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/

## Defender For Endpoint
```KQL
//visualise emails tagged as malware inbound
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection =~ "Inbound"
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```

```KQL
//internal to internal, or outbound email with a malware detection
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection !~ "Inbound" and SenderFromAddress !~ "postmaster@heathrow.com" and AttachmentCount > 0
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```

## Sentinel
```KQL
//visualise emails tagged as malware inbound
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection =~ "Inbound"
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```

```KQL
//internal to internal, or outbound email with a malware detection
EmailEvents
| where TimeGenerated > ago(30d) and ThreatTypes has_any ("Malware") and EmailDirection !~ "Inbound" and SenderFromAddress !~ "postmaster@heathrow.com" and AttachmentCount > 0
| summarize emails=count() by bin(TimeGenerated, 1d), SenderFromAddress
| render columnchart kind=stacked
```
