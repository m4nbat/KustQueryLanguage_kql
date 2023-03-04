# Qakbot

`// Use this query to find email stealing activities ran by Qakbot that will use "ping.exe -t 127.0.0.1" to obfuscate subsequent actions.
// Email theft that occurs might be exfiltrated to operators and indicates that the malware completed a large portion of its automated activity without interruption.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Qakbot%20email%20theft%20(1).yaml
DeviceFileEvents
| where InitiatingProcessFileName =~ 'ping.exe' and InitiatingProcessCommandLine == 'ping.exe -t 127.0.0.1'
    and InitiatingProcessParentFileName in~('msra.exe', 'mobsync.exe') and FolderPath endswith ".eml"`

`// Use this query to find reconnaissance and beaconing activities after code injection occurs.
// Reconnaissance commands are consistent with the current version of Qakbot and occur automatically to exfiltrate system information. This data, once exfiltrated, will be used to prioritize human operated actions.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Qakbot%20reconnaissance%20activities.yaml
DeviceProcessEvents
| where InitiatingProcessFileName == InitiatingProcessCommandLine
| where ProcessCommandLine has_any (
"whoami /all","cmd /c set","arp -a","ipconfig /all","net view /all","nslookup -querytype=ALL -timeout=10",
"net share","route print","netstat -nao","net localgroup")
| summarize dcount(FileName), make_set(ProcessCommandLine) by DeviceId,bin(Timestamp, 1d), InitiatingProcessFileName, InitiatingProcessCommandLine
| where dcount_FileName >= 8`


`// Qakbot operators have been abusing the Craigslist messaging system to send malicious emails. These emails contain non-clickable links to malicious domains impersonating Craigslist, which the user is instructed to manually type into the address bar to access.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Qakbot%20Craigslist%20Domains.yaml
DeviceNetworkEvents
| where RemoteUrl matches regex @"abuse\.[a-zA-Z]\d{2}-craigslist\.org"`


`// This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
// Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
// The following query detects if Qakbot has injected code into the ping.exe process, to evade security and access credentials.
// Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Defense%20evasion/qakbot-campaign-process-injection.yaml
DeviceProcessEvents
| where FileName == "esentutl.exe"
| where ProcessCommandLine has "WebCache"
| where ProcessCommandLine has_any ("V01", "/s", "/d")
| project ProcessCommandLine, InitiatingProcessParentFileName, 
DeviceId, Timestamp`


`// Use this query to find Excel launching anomalous processes congruent with Qakbot payloads which contain additional markers from recent Qakbot executions.
// The presence of such anomalous processes indicate that the payload was delivered and executed, though reconnaissance and successful implantation hasn't been completed yet.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Excel%20launching%20anomalous%20processes.yaml
DeviceProcessEvents
| where InitiatingProcessParentFileName has "excel.exe" or InitiatingProcessFileName =~ "excel.exe"
| where InitiatingProcessFileName in~ ("excel.exe","regsvr32.exe")
| where FileName in~ ("regsvr32.exe", "rundll32.exe")| where ProcessCommandLine has @"..\"`


`// Use this query to find Excel launching anomalous processes congruent with Qakbot payloads which contain additional markers from recent Qakbot executions.
// The presence of such anomalous processes indicate that the payload was delivered and executed, though reconnaissance and successful implantation hasn't been completed yet.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Excel%20launching%20anomalous%20processes.yaml
DeviceProcessEvents
| where InitiatingProcessParentFileName has "excel.exe" or InitiatingProcessFileName =~ "excel.exe"
| where InitiatingProcessFileName in~ ("excel.exe","regsvr32.exe")
| where FileName in~ ("regsvr32.exe", "rundll32.exe")| where ProcessCommandLine has_all (@"..\","DllRegisterServer")`

`// Use this query to find Excel launching anomalous processes congruent with Qakbot payloads which contain additional markers from recent Qakbot executions.
// The presence of such anomalous processes indicate that the payload was delivered and executed, though reconnaissance and successful implantation hasn't been completed yet.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Excel%20launching%20anomalous%20processes.yaml
DeviceProcessEvents
| where InitiatingProcessParentFileName has "excel.exe" or InitiatingProcessFileName =~ "excel.exe"
| where InitiatingProcessFileName in~ ("excel.exe","regsvr32.exe")
| where FileName in~ ("regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_all ("regsvr32.exe","-s",".dll")`

`// This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
// Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
// The following query detects possible attempts by Qakbot to execute malicious Javascript code.
// Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Execution/qakbot-campaign-suspicious-javascript.yaml
DeviceProcessEvents
| where InitiatingProcessFileName == "cmd.exe"
| where FileName == "cscript.exe"
| where InitiatingProcessCommandLine has "start /MIN"
| where ProcessCommandLine has "E:javascript"
| project ProcessCommandLine, 
InitiatingProcessCommandLine, DeviceId, Timestamp`

`// This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
// Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
// The following query detects registry entries that may indicate that an operator is trying to establish persistence for the Qakbot binary.
// Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Persistence/qakbot-campaign-registry-edit.yaml
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "explorer.exe"
| where RegistryValueData has @"AppData\Roaming\Microsoft" and
RegistryValueData has "$windowsupdate"
| where RegistryKey has @"CurrentVersion\Run"
| project RegistryKey, RegistryValueData, DeviceId, Timestamp`

`// Use this query to locate injected processes launching discovery activity. Qakbot has been observed leading to ransomware in numerous instances.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Ransomware/Qakbot%20discovery%20activies.yaml
DeviceProcessEvents 
| where InitiatingProcessFileName in~('mobsync.exe','explorer.exe')
| where (FileName =~ 'net.exe' and InitiatingProcessCommandLine has_all('view','/all'))
     or (FileName =~ 'whoami.exe' and InitiatingProcessCommandLine has '/all')
     or (FileName =~ 'nslookup.exe' and InitiatingProcessCommandLine has_all('querytype=ALL','timeout=10'))
     or (FileName =~ 'netstat.exe' and InitiatingProcessCommandLine has '-nao')
     or (FileName =~ 'arp.exe' and InitiatingProcessCommandLine has '-a')
     or (FileName =~ 'ping.exe' and InitiatingProcessCommandLine has '-t' and InitiatingProcessCommandLine endswith '127.0.0.1')
| summarize DiscoveryCommands = dcount(InitiatingProcessCommandLine), make_set(InitiatingProcessFileName), make_set(FileName), make_set(InitiatingProcessCommandLine) by DeviceId, bin(Timestamp, 5m)   
| where DiscoveryCommands >= 3`

`// Use this query to find email stealing activities ran by Qakbot that will use "ping.exe -t 127.0.0.1" to obfuscate subsequent actions.
// Email theft that occurs might be exfiltrated to operators and indicates that the malware completed a large portion of its automated activity without interruption.
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Campaigns/Qakbot/Qakbot%20email%20theft%20(1).yaml
DeviceFileEvents
| where InitiatingProcessFileName =~ 'ping.exe' and InitiatingProcessCommandLine == 'ping.exe -t 127.0.0.1'
    and InitiatingProcessParentFileName in~('msra.exe', 'mobsync.exe') and FolderPath endswith ".eml"`


`// This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
// Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
// The following query detects if an instance of Qakbot has attempted to overwrite its original binary.
// Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Defense%20evasion/qakbot-campaign-self-deletion.yaml
DeviceProcessEvents 
| where FileName =~ "ping.exe"
| where InitiatingProcessFileName =~ "cmd.exe"
| where InitiatingProcessCommandLine has "calc.exe" and
InitiatingProcessCommandLine has "-n 6" 
and InitiatingProcessCommandLine has "127.0.0.1"
| project ProcessCommandLine, InitiatingProcessCommandLine,
InitiatingProcessParentFileName, DeviceId, Timestamp`

`// This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
// Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
// The following query detects attempts to access files in the local path that contain Outlook emails.
// Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
// This query was updated from https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries/Microsoft%20365%20Defender/Discovery/qakbot-campaign-outlook.yaml
DeviceFileEvents
| where FolderPath hasprefix "EmailStorage"
| where FolderPath has "Outlook"
| project FileName, FolderPath, InitiatingProcessFileName,
InitiatingProcessCommandLine, DeviceId, Timestamp`

`//Scheduled task names and execution
//ATT&CK technique(s): T1053.005 Scheduled Task/Job: Scheduled Task,T1218.010 Signed //Binary Proxy Execution: Regsvr32
//ATT&CK tactic(s): Persistence, Defense Evasion
//Details: The more things change, the more they stay the same. One of the most consistent ways we have detected Qbot over the years is through its use of scheduled tasks for persistence. While Qbot has consistently relied on this method of persisting, its implementation has varied over time. These variations have triggered several different detection analytics.
//One area to focus on is the name of the scheduled task. We often observe this in the /tn (task name) parameter on the command line of schtasks.exe. Much like the subfolders containing the malware, some versions of Qbot have used a random string for the scheduled task name. This is a bit more challenging to detect, but using trigram analysis, we have been able to identify likely random task names that unearth a variety of pernicious persistence. In addition to the scheduled task name, the process it executes can also be useful for detection. In the below example (showing the more recent DLL variation of Qbot), you can see that the process executed by the task is regsvr32.exe. It is unusual to see a scheduled task executing regsvr32.exe at all, let alone for a binary in a user’s profile folder, so looking for that execution presents another detection opportunity.
DeviceProcessEvents
| where (InitiatingProcessParentFileName =~ "explorer.exe" or InitiatingProcessFileName =~ "explorer.exe")
| where (ProcessCommandLine has_all ("c:\\Windows\\system32\\schtasks.exe","/Create","/RU","NT AUTHORITY\\SYSTEM","/tn","/tr","regsvr32.exe","-s","C:\\Users\\","/SC","ONCE","/Z") or InitiatingProcessCommandLine has_all ("c:\\Windows\\system32\\schtasks.exe","/Create","/RU","NT AUTHORITY\\SYSTEM","/tn","/tr","regsvr32.exe","-s","C:\\Users\\","/SC","ONCE","/Z")) `

`//Scheduled task names and execution
//ATT&CK technique(s): T1053.005 Scheduled Task/Job: Scheduled Task,T1218.010 Signed //Binary Proxy Execution: Regsvr32
//ATT&CK tactic(s): Persistence, Defense Evasion
//Details: The more things change, the more they stay the same. One of the most consistent ways we have detected Qbot over the years is through its use of scheduled tasks for persistence. While Qbot has consistently relied on this method of persisting, its implementation has varied over time. These variations have triggered several different detection analytics.
//In other cases, instead of a random string of characters, Qbot uses a GUID for the scheduled task name. Since GUIDs use a similar pattern, you can create a detection analytic looking for schtasks.exe along with create and a regular expression for the GUID pattern. You may still encounter some legitimate software doing this, but it should be fairly straightforward to tune out the noise based on the parent process of schtasks or by the specific GUID itself.
//In addition to the scheduled task name, you can also look for what is being executed, similar to the above example. In the below example, the GUID task name executes JavaScript stored in a file with a .npl file extension. You could create a detection analytic looking for scheduled task execution of a .npl file, or even take it a step further to look for cscript.exe or wscript.exe execution from scheduled tasks (though that may take some tuning).
DeviceProcessEvents
| where (InitiatingProcessParentFileName =~ "mobsync.exe" or InitiatingProcessFileName =~ "mobsync.exe")
| where (ProcessCommandLine has_all ("c:\\Windows\\system32\\schtasks.exe","/Create","/tn","/tr","cmd.exe","regsvr32.exe","-s","C:\\Users\\",":javascript","ONCE","/Z","/MIN","C:\\Windows\\System32\\cscript.exe") or InitiatingProcessCommandLine has_all ("c:\\Windows\\system32\\schtasks.exe","/Create","/tn","/tr","cmd.exe","regsvr32.exe","-s","C:\\Users\\",":javascript","ONCE","/Z","/MIN","C:\\Windows\\System32\\cscript.exe"))`

