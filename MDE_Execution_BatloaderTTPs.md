# BatLoader Malware Execution Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |

#### Description
Detects BatLoader malware execution patterns including suspicious PowerShell execution from AppData with web request patterns and Gpg4Win tool abuse used by BatLoader for payload delivery.

#### Risk
BatLoader is an evasive downloader malware that uses legitimate tools like Gpg4Win to evade defenses. It is often used as a first-stage loader delivering banking trojans, information stealers, and ransomware.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html

## Defender For Endpoint
```KQL
//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'powershell.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'\powershell.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'gpg2.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'gpg2.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

## Sentinel
```KQL
//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'powershell.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'\powershell.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'gpg2.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```

```KQL
// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'gpg2.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')
```
