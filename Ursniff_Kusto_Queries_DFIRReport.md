# Ursniff Kusto Queries

# Source: https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts/

# Driverquery Lookup
`//Driverquery Lookup
//Detects use of driverquery to look up the installed and configured drivers as part of host discovery
//https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/driverquery
//https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
DeviceProcessEvents | where (FolderPath endswith @'\driverquery.exe' and ProcessCommandLine contains @'driverquery' and InitiatingProcessFolderPath endswith @'\cmd.exe' and InitiatingProcessCommandLine contains @'/c')`

# Mshta Executing from Registry
`//Mshta Executing from Registry
//Detects a Mshta executing code from the registry
//https://lolbas-project.github.io/lolbas/Binaries/Mshta/
//https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
DeviceProcessEvents | where (ProcessCommandLine contains @'wscript.shell' and ProcessCommandLine contains @'new ActiveXObject' and ProcessCommandLine contains @'regread' and FolderPath endswith @'mshta.exe')`

# windows-commands- nslookup
`//https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup
//https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
DeviceProcessEvents | where (FolderPath endswith @'\nslookup.exe' and ProcessCommandLine contains @'127.0.0.1' and InitiatingProcessFolderPath endswith @'\cmd.exe' and InitiatingProcessCommandLine contains @'/c')`

# System Time Lookup
`//System Time Lookup - Detects use of time to look up the system time as part of host discovery
//https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/time
//https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
DeviceProcessEvents | where (ProcessCommandLine contains @'/c' and ProcessCommandLine contains @'time' and FolderPath endswith @'\cmd.exe')`

# Ursnif Loader
`//Ursnif Loader
//Detects a very specific command the Ursnif loader runs.
//https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/time
//https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
DeviceProcessEvents | where (ProcessCommandLine contains @'/C' and ProcessCommandLine contains @'pause dll mail' and FolderPath endswith @'syswow64\cmd.exe')`

# LOLBIN From Abnormal Drive
`//LOLBIN From Abnormal Drive - Detects LOLBINs executing from an abnormal drive such as a mounted ISO.
//https://thedfirreport.com/2021/12/13/diavol-ransomware/
//https://www.scythe.io/library/threat-emulation-qakbot
// Rare false positives could occur on servers with multiple drives.
DeviceProcessEvents | where ((* contains @'\rundll32.exe' or * contains @'\calc.exe' or * contains @'\mshta.exe' or * contains @'\cscript.exe' or * contains @'\wscript.exe' or * contains @'\regsvr32.exe' or * contains @'\installutil.exe' or * contains @'\cmstp.exe') and not ((CurrentDirectory contains @'C:\' or CurrentDirectory =~ @'') or isempty(CurrentDirectory)))`

# Detects Wscript or Cscript executing from a drive other than C
`//Detects Wscript or Cscript executing from a drive other than C. This has been observed with Qakbot executing from within a mounted ISO file.
//Wscript Execution from Non C Drive
 //https://github.com/pr0xylife/Qakbot/blob/main/Qakbot_BB_30.09.2022.txt
//https://app.any.run/tasks/4985c746-601e-401a-9ccf-ae350ac2e887/
//Legitimate applications installed on other partitions such as "D:"
DeviceProcessEvents | where (((FolderPath endswith @'\wscript.exe' or FolderPath endswith @'\cscript.exe') and (ProcessCommandLine contains @'.js' or ProcessCommandLine contains @'.vbs' or ProcessCommandLine contains @'.vbe') and ProcessCommandLine contains @':\') and not ((ProcessCommandLine contains @' C:\\' or ProcessCommandLine contains @' 'C:\' or ProcessCommandLine contains @' "C:\\') or ProcessCommandLine contains @'%' or ProcessCommandLine contains @' \\\\'))`

# Suspicious Get ComputerSystem Information with WMIC
`//Suspicious Get ComputerSystem Information with WMIC - Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model...etc.
//https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
DeviceProcessEvents | where ((FolderPath endswith @'\wmic.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'wmic.exe' or ProcessVersionInfoOriginalFileName =~ @'wmic.exe') and (ProcessCommandLine contains @' computersystem ' and ProcessCommandLine contains @' get '))`

# Suspicious Execution of Systeminfo
`//Suspicious Execution of Systeminfo - Detects usage of the "systeminfo" command to retrieve information
//https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-1---system-information-discovery
//https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo
DeviceProcessEvents | where (FolderPath endswith @'\systeminfo.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'sysinfo.exe' or ProcessVersionInfoOriginalFileName =~ @'sysinfo.exe')`

# Wmiexec Default Output File
`//Wmiexec Default Output File - Detects the creation of the default output filename used by the wmicexec tool
//https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/
DeviceFileEvents | where (FolderPath matches regex @'(?i)\\Windows\\__1\d{9}\.\d{1,7}$')`

# Impacket Lateralization Detection 
`//Impacket Lateralization Detection - Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
//https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/wmiexec.py
//https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/atexec.py
//https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/smbexec.py
//https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/dcomexec.py
DeviceProcessEvents | where (((InitiatingProcessFolderPath endswith @'\wmiprvse.exe' or InitiatingProcessFolderPath endswith @'\mmc.exe' or InitiatingProcessFolderPath endswith @'\explorer.exe' or InitiatingProcessFolderPath endswith @'\services.exe') and ProcessCommandLine contains @'cmd.exe' and ProcessCommandLine contains @'/Q' and ProcessCommandLine contains @'/c' and ProcessCommandLine contains @'\\\\127.0.0.1\\' and ProcessCommandLine contains @'&1') or ((InitiatingProcessCommandLine contains @'svchost.exe -k netsvcs' or InitiatingProcessCommandLine contains @'taskeng.exe') and ProcessCommandLine contains @'cmd.exe' and ProcessCommandLine contains @'/C' and ProcessCommandLine contains @'Windows\Temp\' and ProcessCommandLine contains @'&1'))`

# SplashTop Process - Detects use of SplashTop
`//SplashTop Process - Detects use of SplashTop
//https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/212724303-Why-does-the-Splashtop-software-show-unable-to-reach-Splashtop-servers-
//https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
//Legitimate use of SplashTop installation
DeviceProcessEvents | where (Product contains @'SplashTop' and (ProcessVersionInfoFileDescription contains @'SplashTop' or InitiatingProcessVersionInfoFileDescription contains @'SplashTop'))`

# SplashTop Network Connection - Detects use of SplashTop
`//SplashTop Network Connection - Detects use of SplashTop
//https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/212724303-Why-does-the-Splashtop-software-show-unable-to-reach-Splashtop-servers-
//https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
//Legitimate use of SplashTop installation
let processes = datatable(procName:string)["\\spupnp.exe","\\Dataproxy.exe","\\SRServer.exe","\\SRFeature.exe","\\SSUService.exe","\\strwinclt.exe"];
DeviceNetworkEvents
| where InitiatingProcessFileName has_any (processes) and RemoteUrl has_any (".splashtop.eu",".spashtop.com")`

# SplashTop Network Connection - Detects use of SplashTop
`//SplashTop Network Connection - Detects use of SplashTop
//https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/212724303-Why-does-the-Splashtop-software-show-unable-to-reach-Splashtop-servers-
//https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
//Legitimate use of SplashTop installation
let processes = datatable(procName:string)["spupnp.exe","Dataproxy.exe","SRServer.exe","SRFeature.exe","SSUService.exe","strwinclt.exe"];
DeviceNetworkEvents
| where InitiatingProcessFileName has_any (processes) and RemoteUrl has_any (".splashtop.eu",".spashtop.com")`

# Active Directory Computers Enumeration with Get-AdComputer
`//Active Directory Computers Enumeration with Get-AdComputer - Detects usage of the "Get-AdComputer" to enumerate Computers within Active Directory.
//https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
// Legitimate admin activity
DeviceProcessEvents
| where (ProcessCommandLine contains @'Get-AdComputer ' and ProcessCommandLine contains @'-Filter')`
