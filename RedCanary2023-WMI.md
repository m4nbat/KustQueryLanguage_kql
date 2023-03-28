# Red Canary Threat Report - Windows Command Shell

**Source:** https://redcanary.com/threat-detection-report/techniques/windows-command-shell/

**Experimental hunting queries based on Red Canary threat report (Untested)**

## Suspicious process lineage
In general, trusted binaries and known administrative tools and processes will initiate WMI activity. As such, it makes sense to look for known bad processes launching WMI or deviations from the expected where a legitimate but unusual Windows binary spawns WMI—or spawns from it. 

**Pseudocode:** parent_process == wmiprvse.exe && process == ('rundll32.exe' || 'msbuild.exe' || 'powershell.exe' || 'cmd.exe' || 'mshta.exe')

**Kusto:**
`DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "wmiprvse.exe" or InitiatingProcessFileName =~ "wmiprvse.exe"
| where InitiatingProcessFileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe") or FileName in~ FileName in~ ("rundll32.exe", "msbuild.exe", "powershell.exe", "cmd.exe", "mshta.exe")`

## Suspicious commands
Looking for suspicious command-line parameters is another solid indicator of malice. Certain red team and post-exploitation frameworks will spawn unique and unsigned binaries or commands remotely using the well known process call create command, and we’ve got a couple different detection methods that have alerted us to related activity over the years. Potentially suspicious WMI command switches include create, node:, process, and call. Of course, the maliciousness of these commands are context-specific, and therefore, the following may require tuning or generate high volumes of false positives.

**Pseudocode** process == wmic.exe && command_includes ('create' || 'node:' || 'process' || 'call')

**Kusto:**
`DeviceProcessEvents
| where (InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe") and (ProcessCommandLine  has_any ("create", "node:", "process", "call") or  InitiatingProcessCommandLine has_any ("create", "node:", "process", "call"))`

## Unusual module loads
By monitoring and detecting on module loads, you can catch a variety of different malicious activities, including defense evasion and credential theft. In cases where an adversary is using WMI for credential theft, consider looking for the execution of wmiprvse.exe (or its child processes) with unusual module loads like samlib.dll or vaultcli.dll. WMI is also a useful vehicle for bypassing application controls, and we commonly see adversaries—real and simulated–using a WMI bypass method called “SquibblyTwo.”

**Pseudocode** process == wmic.exe && command_includes ('format:') && module_load == ('jscript.dll' || 'vbscript.dll') 

**Kusto:**
`DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe" or InitiatingProcessParentFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandline contains "format:" or ProcessCommandline contains "format:"
// work to be done to identify how to link module loads | where InitiatingProcessFileName in~ ("jscript.dll", "vbscript.dll") "wmic.exe" or FileName in~ ("jscript.dll", "vbscript.dll")`

## Office products spawning WMI
It’s almost always malicious when wmic.exe spawns as a child process of Microsoft Office and similar products. As such, it makes sense to examine the chain of execution and follow-on activity when this occurs.

**Pseudocode** parent_process == ('winword.exe' || 'excel.exe') && process == wmic.exe

**Kusto:**
`DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("winword.exe", "excel.exe") or InitiatingProcessFileName in~ ("winword.exe", "excel.exe")
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"`

## WMI reconnaissance
Reconnaissance is harder to detect because it looks very similar to normal admin behavior. Even so, we detect a relatively high volume of adversaries leveraging WMI to quickly gather domain information such as users, groups, or computers in the domain.

**Pseudocode** process == wmic.exe && command_includes ('\ldap' || 'ntdomain')

**Kusto:**
`DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe" or FileName =~ "wmic.exe"
| where InitiatingProcessCommandLine has_any ("\\ldap", "ntdomain") or ProcessCommandLine has_any ("\\ldap", "ntdomain")`
