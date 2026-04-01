# Sandworm - ShadowLink

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.003 | Create or Modify System Process: Windows Service | [Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| T1090.003 | Proxy: Multi-hop Proxy | [Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/) |

#### Description
These queries detect ShadowLink malware activity associated with Sandworm, including alert-based detection and persistence via Windows service installation. ShadowLink leverages Tor for covert command-and-control communication.

#### Risk
ShadowLink is a Sandworm (Russian GRU-linked APT) malware that uses Tor for covert C2 communication. Detection is critical as it indicates potential nation-state compromise with risk of espionage, sabotage, or destructive attacks on targeted infrastructure.

#### Author
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Sandworm Threat Actor Group (MITRE)](https://attack.mitre.org/groups/G0034/)

## Defender For Endpoint

```KQL
//Malware related alert for this variant:
SecurityAlert
| where AlertName contains "ShadowLink"
```

```KQL
//Persistence:
DeviceEvents
| where ActionType == 'ServiceInstalled'
| extend JSON = parse_json(AdditionalFields)
| where JSON.ServiceName has 'tor'
| extend SourceTenant = TenantId
| join kind=leftouter tid_lookup on $left.SourceTenant == $right.id
| project-away id
| summarize count() by name
```
