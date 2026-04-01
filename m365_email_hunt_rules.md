# M365 Email Hunt Rules

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |

#### Description
Email hunting queries for Microsoft 365 Defender to visualise inbound malware detections and detect internal or outbound emails with malware attachments.

#### Risk
Detection of malware in inbound emails or outbound/internal email with malware attachments may indicate an active phishing campaign targeting the organisation or a compromised internal mailbox.

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
