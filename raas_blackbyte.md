# Blackbyte Hunt Rules

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1505.003 | Server Software Component: Web Shell | [Web Shell](https://attack.mitre.org/techniques/T1505/003/) |
| T1490 | Inhibit System Recovery | [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| T1537 | Transfer Data to Cloud Account | [Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) |

#### Description
Hunt queries for Blackbyte ransomware based on a five-day intrusion case study by Microsoft. Covers ProxyShell web shell creation, vssadmin shadow copy manipulation, persistence via Registry Run keys, and exfiltration to Mega.nz.

#### Risk
Blackbyte is a ransomware-as-a-service operation that has targeted critical infrastructure. These detections help identify the distinct TTPs used during Blackbyte intrusions, from initial access via ProxyShell to data exfiltration and destructive ransomware deployment.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/

## Defender For Endpoint

### ProxyShell web shell creation events
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any ("ExcludeDumpster","New-ExchangeCertificate") and ProcessCommandLine has_any ("-RequestFile","-FilePath")
```

### Suspicious vssadmin events
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin","vssadmin.exe") and ProcessCommandLine has "Resize ShadowStorage" and ProcessCommandLine has_any ("MaxSize=401MB"," MaxSize=UNBOUNDED")
```

### Detection for persistence creation using Registry Run keys
```KQL
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet" 
| where (RegistryKey has @"Microsoft\Windows\CurrentVersion\RunOnce" and RegistryValueName == "MsEdgeMsE")  
    or (RegistryKey has @"Microsoft\Windows\CurrentVersion\RunOnceEx" and RegistryValueName == "MsEdgeMsE")
    or (RegistryKey has @"Microsoft\Windows\CurrentVersion\Run" and RegistryValueName == "MsEdgeMsE")
| where RegistryValueData startswith @"rundll32"
| where RegistryValueData endswith @".dll,Default"
| project Timestamp,DeviceId,DeviceName,ActionType,RegistryKey,RegistryValueName,RegistryValueData
```

### Exfiltration to Mega.nz
```KQL
//suitable for hunting exfiltration to mega.nz
DeviceNetworkEvents
| where RemoteUrl contains "g.api.mega.co.nz"
```
