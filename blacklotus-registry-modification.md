# BlackLotus UEFI Bootkit Detection Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1542.003 | Pre-OS Boot: Bootkit | [Bootkit](https://attack.mitre.org/techniques/T1542/003/) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |

#### Description
Detection queries for the BlackLotus UEFI bootkit campaign (CVE-2022-21894). Covers HVCI registry modifications, Microsoft Defender AV disabling behavior, and suspicious winlogon.exe network connections.

#### Risk
BlackLotus is the first publicly known in-the-wild UEFI bootkit bypassing Secure Boot. It can disable HVCI, Windows Defender, and BitLocker. It was observed targeting government and enterprise organizations in 2023.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

## Defender For Endpoint
```KQL
//Registry modification. To turn off HVCI, the installer modifies the registry key HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity by setting the value Enabled to “0” – but only if the key already exists. Threat hunters should examine their environment for this registry key modification
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
```

```KQL
// Outbound network connections from winlogon.exe, particularly to port 80, should be considered highly suspicious. This is the result of the injected HTTP downloader function of BlackLotus connecting to the C2 server or performing network configuration discovery. Microsoft Incident Response observed this connection with Sysmon monitoring on an infected device. Analysis of netstat output on an affected device may also reveal winlogon.exe maintaining a network connection on port 80. Given the configuration capabilities of the implant, the connection may be intermittent.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "winlogon.exe" and RemotePort == 80
```

```KQL
//Registry modification. To turn off HVCI, the installer modifies the registry key HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity by setting the value Enabled to “0” – but only if the key already exists. Threat hunters should examine their environment for this registry key modification
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
```

```KQL
// Outbound network connections from winlogon.exe, particularly to port 80, should be considered highly suspicious. This is the result of the injected HTTP downloader function of BlackLotus connecting to the C2 server or performing network configuration discovery. Microsoft Incident Response observed this connection with Sysmon monitoring on an infected device. Analysis of netstat output on an affected device may also reveal winlogon.exe maintaining a network connection on port 80. Given the configuration capabilities of the implant, the connection may be intermittent.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "winlogon.exe" and RemotePort == 80
```

## Sentinel
```KQL
//Registry modification. To turn off HVCI, the installer modifies the registry key HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity by setting the value Enabled to “0” – but only if the key already exists. Threat hunters should examine their environment for this registry key modification
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
```

```KQL
//BlackLotus disables Microsoft Defender Antivirus as a defense evasion method by patching its drivers and stripping the main process’s privileges. This behavior may produce entries in the Microsoft-Windows-Windows Defender/Operational log in Windows Event Logs. Relevant log entries will indicate that Antimalware security intelligence has stopped functioning for an unknown reason
Event
| where EventLog =~ "Microsoft-Windows-Windows Defender/Operational" and EventID == 3002 and RenderedDescription contains "Antimalware security intelligence has stopped functioning for an unknown reason"
```

```KQL
//The disabling of Microsoft Defender Antivirus may also result in the service stopping unexpectedly, producing an Event ID 7023 in the System event log (with Service Control Manager as the Provider Name). Relevant log entries will name the Microsoft Defender Antivirus Service as the affected service
Event
| where EventLog =~ "System" and EventID == 7023 and RenderedDescription contains "Microsoft Defender Antivirus Service"
```

```KQL
//Outbound network connections from winlogon.exe, particularly to port 80, should be considered highly suspicious. This is the result of the injected HTTP downloader function of BlackLotus connecting to the C2 server or performing network configuration discovery. Microsoft Incident Response observed this connection with Sysmon monitoring on an infected device. Analysis of netstat output on an affected device may also reveal winlogon.exe maintaining a network connection on port 80. Given the configuration capabilities of the implant, the connection may be intermittent.
// sysmon field names may vary based on how your parser is configured
Event
| where EventLog =~ "Microsoft-Windows-Sysmon/Operational" and EventID == 3 and Image endswith "winlogon.exe" and DestinationPort == 80 and DestinatonPortName =~ "http"
```

```KQL
// Outbound network connections from winlogon.exe, particularly to port 80, should be considered highly suspicious. This is the result of the injected HTTP downloader function of BlackLotus connecting to the C2 server or performing network configuration discovery. Microsoft Incident Response observed this connection with Sysmon monitoring on an infected device. Analysis of netstat output on an affected device may also reveal winlogon.exe maintaining a network connection on port 80. Given the configuration capabilities of the implant, the connection may be intermittent.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "winlogon.exe" and RemotePort == 80
```

```KQL
//Registry modification. To turn off HVCI, the installer modifies the registry key HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity by setting the value Enabled to “0” – but only if the key already exists. Threat hunters should examine their environment for this registry key modification
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
```

```KQL
// Outbound network connections from winlogon.exe, particularly to port 80, should be considered highly suspicious. This is the result of the injected HTTP downloader function of BlackLotus connecting to the C2 server or performing network configuration discovery. Microsoft Incident Response observed this connection with Sysmon monitoring on an infected device. Analysis of netstat output on an affected device may also reveal winlogon.exe maintaining a network connection on port 80. Given the configuration capabilities of the implant, the connection may be intermittent.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "winlogon.exe" and RemotePort == 80
```
