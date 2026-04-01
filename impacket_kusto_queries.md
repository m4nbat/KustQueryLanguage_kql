# Impacket Framework Lateral Movement Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB/Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| T1047 | Windows Management Instrumentation | [WMI](https://attack.mitre.org/techniques/T1047/) |

#### Description
Detection queries for Impacket framework lateral movement tools (SMBexec and WMIexec). Uses regex patterns to identify characteristic command patterns used by these tools.

#### Risk
Impacket is widely used by threat actors and penetration testers for lateral movement. SMBexec and WMIexec provide interactive shells via SMB and WMI, commonly seen in ransomware intrusions.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/threats/impacket/
- https://github.com/SecureAuthCorp/impacket

## Defender For Endpoint
```KQL
//SMBexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket smbexec script, which allows a semi-interactive shell used through SMB. The regular expression identifies the name of a file share used to store output from the commands for interaction.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and ProcessCommandLine matches regex @"(?i)cmd.exe\s+\/Q\s+\/c\s+echo\s+cd\s+>\s+\\\\127.0.0.1\\[a-zA-Z]{1,}\$\\__output\s*2\s*>\s*&\s*1\s*>\s+.*\s+&"
```

```KQL
//WMIexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket wmiexec script, which allows a semi-interactive shell used via WMI. This analytic shows output being redirected to the localhost ADMIN$ share. The regular expression identifies an output file named as a Unix timestamp (similar to 1642629756.323274) generated through the script.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse" and InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has_all ("cmd.exe","/Q","/c",@"\\127.0.0.1\ADMIN\$\__","2>&1") and ProcessCommandLine matches regex @"[0-9]{1,10}\.[0-9]{1,10}"
```

## Sentinel
```KQL
//SMBexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket smbexec script, which allows a semi-interactive shell used through SMB. The regular expression identifies the name of a file share used to store output from the commands for interaction.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and ProcessCommandLine matches regex @"(?i)cmd.exe\s+\/Q\s+\/c\s+echo\s+cd\s+>\s+\\\\127.0.0.1\\[a-zA-Z]{1,}\$\\__output\s*2\s*>\s*&\s*1\s*>\s+.*\s+&"
```

```KQL
//WMIexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket wmiexec script, which allows a semi-interactive shell used via WMI. This analytic shows output being redirected to the localhost ADMIN$ share. The regular expression identifies an output file named as a Unix timestamp (similar to 1642629756.323274) generated through the script.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse" and InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has_all ("cmd.exe","/Q","/c",@"\\127.0.0.1\ADMIN\$\__","2>&1") and ProcessCommandLine matches regex @"[0-9]{1,10}\.[0-9]{1,10}"
```
