# Impacket

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | [Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| T1047 | Windows Management Instrumentation | [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) |

#### Description
Detects Impacket toolset usage via SMBexec and WMIexec scripts. SMBexec creates a semi-interactive shell using SMB by executing commands via services.exe and cmd.exe, using a temporary file share for output. WMIexec provides remote shell access via WMI, with output redirected to the ADMIN$ share using Unix timestamp-named files.

#### Risk
Impacket is a widely used attacker toolkit for lateral movement and remote execution without deploying additional binaries. Detection of these specific command-line patterns can identify post-exploitation activity such as lateral movement and remote command execution in progress.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/threats/impacket/

## Defender For Endpoint

### Impacket SMBexec execution

```KQL
//SMBexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket smbexec script, which allows a semi-interactive shell used through SMB. The regular expression identifies the name of a file share used to store output from the commands for interaction.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and ProcessCommandLine matches regex @"(?i)cmd.exe\s+\/Q\s+\/c\s+echo\s+cd\s+>\s+\\\\127.0.0.1\\[a-zA-Z]{1,}\$\\__output\s*2\s*>\s*&\s*1\s*>\s+.*\s+&"
```

### Impacket WMIexec execution

```KQL
//WMIexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket wmiexec script, which allows a semi-interactive shell used via WMI. This analytic shows output being redirected to the localhost ADMIN$ share. The regular expression identifies an output file named as a Unix timestamp (similar to 1642629756.323274) generated through the script.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse" and InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has_all ("cmd.exe","/Q","/c",@"\\127.0.0.1\ADMIN\$\__","2>&1") and ProcessCommandLine matches regex @"[0-9]{1,10}\.[0-9]{1,10}"
```
