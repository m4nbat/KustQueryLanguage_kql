# Title
Phishing abusing .ZIP domains

# Description


# MITRE ATT&CK
- Initial Access
- Phishing: Malicious Link

# Source
- Steven Lim
- 
https://www.linkedin.com/pulse/defending-against-zip-domain-phishing-attack-microsoft-steven-lim?utm_source=share&utm_medium=member_android&utm_campaign=share_via

# Query

## MDE or Sentinel

```
EmailUrlInfo
| where Timestamp > ago(1h)
| where UrlDomain endswith ".zip"
| where Url contains "@"
| join EmailEvents on $left.NetworkMessageId == $right.NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, ThreatTypes, EmailAction, ReportId

```

## MDE or Sentinel - Unicode Abuse 

```

EmailUrlInfo
| where Timestamp > ago(1h)
| where UrlDomain endswith ".zip" and Url contains "%E2%88%95" or Url contains "%E2%81%84" and Url contains "@"
| join EmailEvents on $left.NetworkMessageId == $right.NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, ThreatTypes, EmailAction, ReportId

```
