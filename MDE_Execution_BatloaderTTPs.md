# Batloader Execution Procedures

`//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'powershell.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')`

`//Suspicious BatLoader Malware Execution by Use of Powershell (via cmdline)
//https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'\powershell.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')`

`// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
SecurityEvent 
| where EventID == 4688 
| where NewProcessName endswith @'gpg2.exe' and CommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')`

`// Possible Batloader Malware Execution by Gpg4Win Tool (via process creation)
// https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
DeviceProcessEvents 
| where FileName endswith @'gpg2.exe' and ProcessCommandLine has_all (@'\AppData\Roaming',@'Invoke-WebRequest','OutFile','update.bat','Start-Process')`
