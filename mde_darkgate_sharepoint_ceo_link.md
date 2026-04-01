# Darkgate SharePoint CEO Link

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects DarkGate malware distribution via Microsoft Teams messages containing SharePoint links, including links masquerading as CEO-related SharePoint content. The queries look for suspicious SharePoint URLs in Teams click events and network connections.

#### Risk
Threat actors use Teams messages with malicious SharePoint links to distribute DarkGate malware. Links containing "ceo" in the SharePoint URL path may indicate targeted spearphishing campaigns against high-value employees.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- Intrusion Analysis

## Defender For Endpoint
```KQL
UrlClickEvents
| where Workload =~ "Teams"
| where Url matches regex @"https:\/\/[a-zA-Z0-9-_]+\.sharepoint\.com\/:[a-zA-Z]:\/g\/personal\/[a-zA-Z0-9_]+_onmicrosoft_com"
```

```KQL
DeviceNetworkEvents
| where RemoteUrl has_all ("ceo",".sharepoint.com","_onmicrosoft_com")
```

```KQL
UrlClickEvents
| where Url has_all ("ceo",".sharepoint.com","_onmicrosoft_com")
```

```KQL
DeviceNetworkEvents
| where RemoteUrl matches regex @"https:\/\/[a-zA-Z0-9-_]+\.sharepoint\.com\/:[a-zA-Z]:\/g\/personal\/[a-zA-Z0-9_]+_onmicrosoft_com"
```
