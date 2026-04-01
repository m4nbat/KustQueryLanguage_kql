# Possible MS Teams Phishing Attempt

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |
| T1566.002 | Phishing: Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects possible phishing attempts delivered via Microsoft Teams by identifying external users sending messages with links in one-on-one or group chats, with the initiating IP correlated against threat intelligence indicators. Filters out internal corporate domain users to reduce noise.

#### Risk
Microsoft Teams has become a target for social engineering and phishing campaigns, where attackers send malicious links or files from external accounts. Correlation with threat intelligence allows detection of known-malicious infrastructure being used to deliver phishing lures.

#### Author <Optional>
- **Name:** Steven Lim
- **Github:**
- **Twitter:**
- **LinkedIn:** https://www.linkedin.com/pulse/defending-against-zip-domain-phishing-attack-microsoft-steven-lim
- **Website:**

#### References
- https://www.linkedin.com/pulse/defending-against-zip-domain-phishing-attack-microsoft-steven-lim?utm_source=share&utm_medium=member_android&utm_campaign=share_via

## Sentinel
```KQL
OfficeActivity
| where TimeGenerated > ago(1h)
| where RecordType =~ 'MicrosoftTeams'
| where Operation == "MessageCreatedHasLink"
| where CommunicationType == "OneOnOne" or CommunicationType == "GroupChat"
| where UserId !endswith "your_corporate_domain_1"     // Filter off all internal teams user 1-to-1 message
and UserId !endswith "your_corporate_domain_2"
and UserId !endswith "your_corporate_domain_3"
| extend UserDomains = tostring(split(UserId, '@')[1])
| extend UserIPs = tostring(split(ClientIP, '::ffff:')[1])
| where UserIPs != ""
| distinct UserIPs
| join ThreatIntelligenceIndicator on $left.UserIPs == $right.NetworkIP
```
