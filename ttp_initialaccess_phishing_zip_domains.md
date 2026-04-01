# Phishing Abusing .ZIP Domains

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects phishing emails abusing newly introduced .ZIP top-level domains, which can be used to trick users into thinking a URL is a file archive. Includes a standard detection for emails containing .ZIP domain URLs with an @ symbol (used to redirect browsers), and a Unicode abuse variant using lookalike slash characters to further obfuscate the link.

#### Risk
Attackers can craft .ZIP domain URLs that visually resemble file archive names to trick users into clicking malicious links. The Unicode abuse variant makes the URL even harder to identify as malicious, increasing the likelihood of a successful phishing attack.

#### Author <Optional>
- **Name:** Steven Lim
- **Github:**
- **Twitter:**
- **LinkedIn:** https://www.linkedin.com/pulse/defending-against-zip-domain-phishing-attack-microsoft-steven-lim
- **Website:**

#### References
- https://www.linkedin.com/pulse/defending-against-zip-domain-phishing-attack-microsoft-steven-lim?utm_source=share&utm_medium=member_android&utm_campaign=share_via

## Defender For Endpoint

### Phishing emails with .ZIP domain URLs
```KQL
EmailUrlInfo
| where Timestamp > ago(1h)
| where UrlDomain endswith ".zip"
| where Url contains "@"
| join EmailEvents on $left.NetworkMessageId == $right.NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, ThreatTypes, EmailAction, ReportId
```

### Phishing emails with .ZIP domain URLs abusing Unicode lookalike slash characters
```KQL
EmailUrlInfo
| where Timestamp > ago(1h)
| where UrlDomain endswith ".zip" and Url contains "%E2%88%95" or Url contains "%E2%81%84" and Url contains "@"
| join EmailEvents on $left.NetworkMessageId == $right.NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, ThreatTypes, EmailAction, ReportId
```
