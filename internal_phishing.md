# Internal Phishing Kusto Queries

`EmailEvents
| where EmailDirection =~ "Intra-org" and isnotempty(ThreatTypes)
| summarize count() by ThreatTypes`

`EmailEvents
| where EmailDirection =~ "Intra-org" and ThreatTypes =~ "malware"`

`EmailEvents
| where EmailDirection =~ "Intra-org" and ThreatTypes =~ "phish"`

`EmailEvents
| where EmailDirection =~ "Intra-org" and isnotempty(ThreatTypes)
| summarize count() by ThreatTypes`
