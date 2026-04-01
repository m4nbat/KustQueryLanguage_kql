# Red Canary 2023: Ingress Tool Transfer Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |

#### Description
Detection queries for malicious tool transfer activity based on Red Canary 2023 threat report. Covers suspicious PowerShell download commands, certutil URL cache abuse, and BITSAdmin downloads.

#### Risk
After gaining initial access, adversaries transfer attack tools into victim environments using PowerShell, certutil, and bitsadmin. These are common second-stage payload delivery mechanisms used by many threat actors.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/ingress-tool-transfer/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ('downloadstring','downloadata','downloadfile','iex','.invoke','invoke-expression')
```

```KQL
DeviceProcessEvents
| where FileName =~ "certutil.exe" and ProcessCommandLine has_any ('urlcache','split')
```

```KQL
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ('download','transfer')
```

## Sentinel
```KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ('downloadstring','downloadata','downloadfile','iex','.invoke','invoke-expression')
```

```KQL
DeviceProcessEvents
| where FileName =~ "certutil.exe" and ProcessCommandLine has_any ('urlcache','split')
```

```KQL
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ('download','transfer')
```
