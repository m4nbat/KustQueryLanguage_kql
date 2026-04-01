# MDE SmartScreen Events

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |

#### Description
Detects Microsoft SmartScreen security events, including app warnings, exploit warnings, URL warnings, and user overrides of SmartScreen prompts. SmartScreen events can indicate attempts to download or execute potentially malicious content.

#### Risk
SmartScreen warning events, especially user overrides, may indicate social engineering attacks where users are tricked into bypassing security warnings to execute malware or visit malicious websites.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://twitter.com/ellishlomo/status/1655097765565722629

## Defender For Endpoint
```KQL
let SmartScreenActions = dynamic([
"SmartScreenAppWarning",
"SmartScreenExploitWarning",
"SmartScreenUrlWarning",
"SmartScreenUserOverride"
]);
DeviceEvents
| where ActionType has_any (SmartScreenActions)
```
