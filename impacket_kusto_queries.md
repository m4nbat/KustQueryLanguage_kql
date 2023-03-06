# Impacket

# Source: https://redcanary.com/threat-detection-report/threats/impacket/

## Impacket SMBexec execution

`//SMBexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket smbexec script, which allows a semi-interactive shell used through SMB. The regular expression identifies the name of a file share used to store output from the commands for interaction.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe" and ProcessCommandLine matches regex @"(?i)cmd.exe\s+\/Q\s+\/c\s+echo\s+cd\s+>\s+\\\\127.0.0.1\\[a-zA-Z]{1,}\$\\__output\s*2\s*>\s*&\s*1\s*>\s+.*\s+&"`

## Impacket WMIexec execution

`//WMIexec execution
//This detection analytic uses a regular expression to identify commands from the Impacket wmiexec script, which allows a semi-interactive shell used via WMI. This analytic shows output being redirected to the localhost ADMIN$ share. The regular expression identifies an output file named as a Unix timestamp (similar to 1642629756.323274) generated through the script.
// Regex needs testing with current impacket logs
//Source: https://redcanary.com/threat-detection-report/threats/impacket/
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse" and InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessCommandLine has_all ("cmd.exe","/Q","/c",@"\\127.0.0.1\ADMIN\$\__","2>&1") and ProcessCommandLine matches regex @"[0-9]{1,10}\.[0-9]{1,10}"`
