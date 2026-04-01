# MDE Tampering Event

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |

#### Description
Detects tampering attempts against Microsoft Defender for Endpoint using the `TamperingAttempt` action type in DeviceEvents. The query parses the additional fields to surface the status and target of each tampering attempt, helping analysts identify efforts to disable or modify endpoint protection.

#### Risk
Tampering with endpoint security tools is a common pre-ransomware and APT tactic. Successfully disabling Defender for Endpoint leaves hosts unprotected and blind to subsequent malicious activity, including credential theft, lateral movement, and ransomware deployment.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:** https://twitter.com/ellishlomo
- **LinkedIn:**
- **Website:**

#### References
- https://twitter.com/ellishlomo/status/1653622838949969925

## Defender For Endpoint
```KQL
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend Status = AdditionalInfo.['Status']
| extend Target = AdditionalInfo.['Target']
```
