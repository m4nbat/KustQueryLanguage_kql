# DarkGate MDE Detections

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
Detects DarkGate command and control activity based on port and HTTP request patterns. DarkGate uses port 2351 with HTTP POST requests for C2 communications.

#### Risk
DarkGate C2 communications over port 2351 using HTTP POST requests may indicate an active malware infection and remote control of the compromised host.

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
DeviceNetworkEvents
| where TimeGenerated > ago(60d)
| extend HTTPMethod = tostring(AdditionalFields.method)
| where ActionType =~ "HttpConnectionInspected" and RemotePort == 2351 and HTTPMethod =~ "POST"
| extend direction = tostring(AdditionalFields.direction)
| extend host = tostring(AdditionalFields.host)
| extend request_body_len = tostring(AdditionalFields.request_body_len)
| extend response_body_len = tostring(AdditionalFields.response_body_len)
| extend status_code = tostring(AdditionalFields.status_code)
| extend status_msg = tostring(AdditionalFields.status_msg)
| extend tags = tostring(parse_json(tostring(AdditionalFields.tags)))
| extend trans_depth = tostring(AdditionalFields.trans_depth)
| extend uri = tostring(AdditionalFields.uri)
| extend user_agent = tostring(AdditionalFields.user_agent)
| extend version_ = tostring(AdditionalFields.version)
```
