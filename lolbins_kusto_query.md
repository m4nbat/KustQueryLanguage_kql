# Living-Off-The-Land Binaries (LOLBins) Activity Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218 | Signed Binary Proxy Execution | [Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

#### Description
Catch-all detection for LOLBin (Living-Off-The-Land Binary) execution. Monitors for use of a broad set of Windows utilities commonly abused by adversaries, with frequency analysis to identify anomalous bursts of activity.

#### Risk
LOLBins allow adversaries to blend malicious activity with legitimate administrative tasks. High volumes of LOLBin execution in a short period is a strong indicator of post-compromise discovery or lateral movement.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://lolbas-project.github.io/

## Defender For Endpoint
```KQL
//let excludedProcesses = datatable (name:string)["mssense.exe","senseir.exe"]; //add exclusions
DeviceProcessEvents 
| where FileName has_any (  "arp.exe",  "at.exe",  "attrib.exe",  "cscript.exe",  "dsquery.exe",  "hostname.exe",  "ipconfig.exe",  "mimikatz.exe",  "nbtstat.exe",  "net.exe", "netsh.exe",  "nslookup.exe",  "ping.exe",  "quser.exe",  "qwinsta.exe",  "reg.exe",  "runas.exe",  "sc.exe",  "schtasks.exe",  "ssh.exe",  "systeminfo.exe", "taskkill.exe",  "telnet.exe",  "tracert.exe",  "wscript.exe",  "xcopy.exe",  "pscp.exe",  "copy.exe",  "robocopy.exe",  "certutil.exe",  "vssadmin.exe", "powershell.exe",  "wevtutil.exe",  "psexec.exe",  "bcedit.exe",  "wbadmin.exe",  "icacls.exe",  "diskpart.exe",  "ver.exe",  "netstat.exe",  "tasklist.exe", "route.exe",  "driverquery.exe"  ) 
//| where InitiatingProcessParentFileName !in~ (excludedProcesses) and InitiatingProcessParentFileName !in~ (excludedProcesses) and FileName !in~ (excludedProcesses) // exclude processes that produce false positives
| summarize firstEvent=min(Timestamp), lastEvent=max(Timestamp), uniqueProcessNames=dcount(FileName), eventTypes=make_set(ActionType), userNames=make_set(AccountName), userDomains=make_set(AccountDomain), processIds=make_set(ProcessId), processCommandLines=make_set(ProcessCommandLine), parentProcessNames=make_set(InitiatingProcessFileName), parentProcessCommandLines=make_set(InitiatingProcessCommandLine), parentProcessPaths=make_set(InitiatingProcessFolderPath), parentProcessIds=make_set(InitiatingProcessId), grandParentProcessNames=make_set(InitiatingProcessParentFileName), grandParentProcessIds=make_set(InitiatingProcessParentId), parentUserDomain=make_set(InitiatingProcessAccountDomain), parentUserName=make_set(InitiatingProcessAccountName), processCompanyName=make_set(ProcessVersionInfoCompanyName), processProductName=make_set(ProcessVersionInfoProductName), processVersion=make_set(ProcessVersionInfoProductVersion), processInternalFileName=make_set(ProcessVersionInfoInternalFileName), processOriginalFileName=make_set(ProcessVersionInfoOriginalFileName), processFileDescription=make_set(ProcessVersionInfoFileDescription), processSize=make_set(FileSize), processSHA256=make_set(SHA256), reportIds=make_set(ReportId), Timestamp=make_list(Timestamp), count() by DeviceName, DeviceId 
| where uniqueProcessNames > 4
| order by firstEvent
```

## Sentinel
```KQL
//let excludedProcesses = datatable (name:string)["mssense.exe","senseir.exe"]; //add exclusions
DeviceProcessEvents 
| where FileName has_any (  "arp.exe",  "at.exe",  "attrib.exe",  "cscript.exe",  "dsquery.exe",  "hostname.exe",  "ipconfig.exe",  "mimikatz.exe",  "nbtstat.exe",  "net.exe", "netsh.exe",  "nslookup.exe",  "ping.exe",  "quser.exe",  "qwinsta.exe",  "reg.exe",  "runas.exe",  "sc.exe",  "schtasks.exe",  "ssh.exe",  "systeminfo.exe", "taskkill.exe",  "telnet.exe",  "tracert.exe",  "wscript.exe",  "xcopy.exe",  "pscp.exe",  "copy.exe",  "robocopy.exe",  "certutil.exe",  "vssadmin.exe", "powershell.exe",  "wevtutil.exe",  "psexec.exe",  "bcedit.exe",  "wbadmin.exe",  "icacls.exe",  "diskpart.exe",  "ver.exe",  "netstat.exe",  "tasklist.exe", "route.exe",  "driverquery.exe"  ) 
//| where InitiatingProcessParentFileName !in~ (excludedProcesses) and InitiatingProcessParentFileName !in~ (excludedProcesses) and FileName !in~ (excludedProcesses) // exclude processes that produce false positives
| summarize firstEvent=min(Timestamp), lastEvent=max(Timestamp), uniqueProcessNames=dcount(FileName), eventTypes=make_set(ActionType), userNames=make_set(AccountName), userDomains=make_set(AccountDomain), processIds=make_set(ProcessId), processCommandLines=make_set(ProcessCommandLine), parentProcessNames=make_set(InitiatingProcessFileName), parentProcessCommandLines=make_set(InitiatingProcessCommandLine), parentProcessPaths=make_set(InitiatingProcessFolderPath), parentProcessIds=make_set(InitiatingProcessId), grandParentProcessNames=make_set(InitiatingProcessParentFileName), grandParentProcessIds=make_set(InitiatingProcessParentId), parentUserDomain=make_set(InitiatingProcessAccountDomain), parentUserName=make_set(InitiatingProcessAccountName), processCompanyName=make_set(ProcessVersionInfoCompanyName), processProductName=make_set(ProcessVersionInfoProductName), processVersion=make_set(ProcessVersionInfoProductVersion), processInternalFileName=make_set(ProcessVersionInfoInternalFileName), processOriginalFileName=make_set(ProcessVersionInfoOriginalFileName), processFileDescription=make_set(ProcessVersionInfoFileDescription), processSize=make_set(FileSize), processSHA256=make_set(SHA256), reportIds=make_set(ReportId), Timestamp=make_list(Timestamp), count() by DeviceName, DeviceId 
| where uniqueProcessNames > 4
| order by firstEvent
```
