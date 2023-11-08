# Title
Blackbyte Hunt Rules

# Description


# Source
https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/

# MITRE ATT&CK
- T1505.003: Server Software Component: Web Shell
- T1490: Inhibit System Recovery
- T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1537: Transfer Data to Cloud Account

## ProxyShell web shell creation events

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("ExcludeDumpster","New-ExchangeCertificate") and ProcessCommandLine has_any ("-RequestFile","-FilePath")
```

## Suspicious vssadmin events

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin","vssadmin.exe") and ProcessCommandLine has "Resize ShadowStorage" and ProcessCommandLine has_any ("MaxSize=401MB"," MaxSize=UNBOUNDED")
```

## Detection for persistence creation using Registry Run keys

```
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet" 
| where (RegistryKey has @"Microsoft\Windows\CurrentVersion\RunOnce" and RegistryValueName == "MsEdgeMsE")  
    or (RegistryKey has @"Microsoft\Windows\CurrentVersion\RunOnceEx" and RegistryValueName == "MsEdgeMsE")
    or (RegistryKey has @"Microsoft\Windows\CurrentVersion\Run" and RegistryValueName == "MsEdgeMsE")
| where RegistryValueData startswith @"rundll32"
| where RegistryValueData endswith @".dll,Default"
| project Timestamp,DeviceId,DeviceName,ActionType,RegistryKey,RegistryValueName,RegistryValueData
```

## Exfiltration

```
//suitable for hunting exfiltration to mega.nz
DeviceNetworkEvents
| where RemoteUrl contains "g.api.mega.co.nz"
```

## Microsoft Defender for Endpoint

The following alerts might indicate threat activity related to this threat. Note, however, that these alerts can be also triggered by unrelated threat activity.

‘CVE-2021-31207’ exploit malware was detected
An active ‘NetShDisableFireWall’ malware in a command line was prevented from executing.
Suspicious registry modification.
‘Rtcore64’ hacktool was detected
Possible ongoing hands-on-keyboard activity (Cobalt Strike)
A file or network connection related to a ransomware-linked emerging threat activity group detected
Suspicious sequence of exploration activities
A process was injected with potentially malicious code
Suspicious behavior by cmd.exe was observed
‘Blackbyte’ ransomware was detected
