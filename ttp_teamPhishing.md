# Title
Possible MS Teams phishing attempt

# Description

# MITRE ATT&CK

- Initial Access
- Phishing: Malicious Attachment
- Phishing: Malicious Link

# Query

```
OfficeActivity
| where TimeGenerated > ago(1h)
| where RecordType =~ 'MicrosoftTeams'
| where Operation == "MessageCreatedHasLink"
| where CommunicationType == "OneOnOne" or CommunicationType == "GroupChat"
| where UserId !endswith "your_corporate_domain_1"     // Filter off all internal teams user 1-to-1 message
and UserId !endswith "your_corporate_domain_2"
and UserId !endswith "your_corporate_domain_3"
| extend UserDomains = tostring(split(UserId, '@')[1])
| extend UserIPs = tostring(split(ClientIP, '::ffff:')[1])
| where UserIPs != ""
| distinct UserIPs
| join ThreatIntelligenceIndicator on $left.UserIPs == $right.NetworkIP
```
