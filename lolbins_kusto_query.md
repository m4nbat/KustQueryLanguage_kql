# Hunt for possible LOLBINS activity

`DeviceProcessEvents
| where FileName has_any (  "arp.exe",  "at.exe",  "attrib.exe",  "cscript.exe",  "dsquery.exe",  "hostname.exe",  "ipconfig.exe",  "mimikatz.exe",  "nbtstat.exe",  "net.exe",
  "netsh.exe",  "nslookup.exe",  "ping.exe",  "quser.exe",  "qwinsta.exe",  "reg.exe",  "runas.exe",  "sc.exe",  "schtasks.exe",  "ssh.exe",  "systeminfo.exe",
  "taskkill.exe",  "telnet.exe",  "tracert.exe",  "wscript.exe",  "xcopy.exe",  "pscp.exe",  "copy.exe",  "robocopy.exe",  "certutil.exe",  "vssadmin.exe",
  "powershell.exe",  "wevtutil.exe",  "psexec.exe",  "bcedit.exe",  "wbadmin.exe",  "icacls.exe",  "diskpart.exe",  "ver.exe",  "netstat.exe",  "tasklist.exe",
  "route.exe",  "driverquery.exe"  )
| summarize firstEvent=min(Timestamp), lastEvent=max(Timestamp), uniqueProcessNames=dcount(FileName), eventTypes=make_set(ActionType), userNames=make_set(AccountName), userDomains=make_set(AccountDomain), processIds=make_set(ProcessId), processCommandLines=make_set(ProcessCommandLine), parentProcessNames=make_set(InitiatingProcessFileName), parentProcessCommandLines=make_set(InitiatingProcessCommandLine), parentProcessPaths=make_set(InitiatingProcessFolderPath), parentProcessIds=make_set(InitiatingProcessId), grandParentProcessNames=make_set(InitiatingProcessParentFileName), grandParentProcessIds=make_set(InitiatingProcessParentId), parentUserDomain=make_set(InitiatingProcessAccountDomain), parentUserName=make_set(InitiatingProcessAccountName), processCompanyName=make_set(ProcessVersionInfoCompanyName), processProductName=make_set(ProcessVersionInfoProductName), processVersion=make_set(ProcessVersionInfoProductVersion), processInternalFileName=make_set(ProcessVersionInfoInternalFileName), processOriginalFileName=make_set(ProcessVersionInfoOriginalFileName), processFileDescription=make_set(ProcessVersionInfoFileDescription), processSize=make_set(FileSize), processSHA256=make_set(SHA256), reportIds=make_set(ReportId), Timestamp=make_list(Timestamp), count() by DeviceName, DeviceId
| order by firstEvent
| where uniqueProcessNames > 4`
