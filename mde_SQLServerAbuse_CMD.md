# SQL Server Abuse

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1505.001 | Server Software Component: SQL Stored Procedures | [Server Software Component: SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001/) |

#### Description
Detects instances of SQL Server processes launching a shell to run suspicious commands. This pattern is associated with threat actors abusing SQL Server to execute living-off-the-land binaries (LOLBins) for lateral movement and privilege escalation.

#### Risk
Adversaries with access to SQL Server may abuse it to execute system commands via xp_cmdshell or other mechanisms, enabling lateral movement to cloud resources and execution of malicious payloads.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://www.microsoft.com/en-us/security/blog/2023/10/03/defending-new-vectors-threat-actors-attempt-sql-server-to-cloud-lateral-movement/

## Defender For Endpoint
```KQL
// This query detects instances of a SQL Server process launching a shell to run one or more suspicious commands.
let relevantCmdlineTokens = pack_array
("advpack.dll","appvlp.exe","atbroker.exe","bash.exe","bginfo.exe","bitsadmin.exe","cdb.exe","certutil.exe","cl_invocation.ps1","cl_mutexverifiers.ps1","cmstp.exe","Copy-Item","csi.exe","diskshadow.exe","dnscmd.exe","dnx.exe","dxcap.exe","esentutl.exe","expand.exe","extexport.exe","extrac32.exe","findstr.exe","forfiles.exe","ftp.exe","gpscript.exe","hh.exe","ie4uinit.exe","ieadvpack.dll","ieaframe.dll","ieexec.exe","infdefaultinstall.exe", "installutil.exe","Invoke-WebRequest","makecab.exe","manage-bde.wsf","mavinject.exe","mftrace.exe","microsoft.workflow.compiler.exe","mmc.exe","msbuild.exe","msconfig.exe","msdeploy.exe","msdt.exe","mshta.exe","mshtml.dll","msiexec.exe","msxsl.exe","netstat","odbcconf.exe","pcalua.exe","pcwrun.exe","pcwutl.dll","pester.bat","ping","presentationhost.exe","pubprn.vbs","rcsi.exe","regasm.exe","register-cimprovider.exe","regsvcs.exe","regsvr32.exe","replace.exe","rundll32.exe","runonce.exe","runscripthelper.exe","schtasks.exe","scriptrunner.exe","setupapi.dll","shdocvw.dll","shell32.dll","slmgr.vbs","sqltoolsps.exe","syncappvpublishingserver.exe","syncappvpublishingserver.vbs","sysinfo","syssetup.dll","systeminfo","taskkill","te.exe","tracker.exe","url.dll","verclsid.exe","vsjitdebugger.exe","wab.exe","WebClient","wget","whoami","winrm.vbs","wmic.exe","xwizard.exe","zipfldr.dll","certutil");
DeviceProcessEvents 
| where Timestamp >= ago(10d)
| where InitiatingProcessFileName in~ ("sqlservr.exe", "sqlagent.exe", "sqlps.exe", "launchpad.exe")
| summarize DistinctProcessCommandLines = tostring(makeset(ProcessCommandLine)) by DeviceId, bin(Timestamp, 2m)  
| where DistinctProcessCommandLines has_any(relevantCmdlineTokens) 
```
