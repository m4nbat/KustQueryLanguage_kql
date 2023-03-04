# Scheduled task persistence from the roaming folder with no command-line arguments
`//Scheduled task persistence from the roaming folder with no command-line arguments
//The following detection analytic looks for scheduled tasks executing from the Users folder. Tasks executing with no command-line arguments are more likely to be malicious. To reduce noise, you will likely need to create exceptions for any approved applications in your environment that have this behavior.
DeviceProcessEvents
| where FileName has_any ("taskeng.exe","svchost.exe") and FolderPath has_all ("users","appdata\\roaming") and isempty(ProcessCommandLine)`
