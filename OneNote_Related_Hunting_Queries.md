# OneNote spawning suspicious child processes
The following pseudo-detection analytic identifies OneNote as a parent process for suspicious child processes. This is not a new type of analytic; historically they have been useful for detecting suspicious Excel child processes. The same type of logic can be leveraged to detect suspicious OneNote activity. This pseudo-analytic would need to be updated as adversaries change which processes they start with OneNote, so an alternative option would be to detect any child processes spawned from Office applications.

## OneNote spawning suspicious child processes
The following detection analytic identifies OneNote as a parent process for suspicious child processes. This is not a new type of analytic; historically they have been useful for detecting suspicious Excel child processes. The same type of logic can be leveraged to detect suspicious OneNote activity. This pseudo-analytic would need to be updated as adversaries change which processes they start with OneNote, so an alternative option would be to detect any child processes spawned from Office applications.


`DeviceProcessEvents
| where InitiatingProcessFileName =~ "onenote.exe" and FileName in~ ("cmd.exe","powershell.exe",wscript.exe,"jscript.exe")`


## OneNote Url connections (can be noisy) good for frequency analysis or enriching with IoA / IoC data

`DeviceEvents
| where ActionType =~ "BrowserLaunchedToOpenUrl" and InitiatingProcessFileName in~ ("onenote.exe") and RemoteUrl !startswith @"C:\Users\"`


## Possible OneNote phishing using a shared link

`let exclusionDomain = datatable(domain:string)["exampledomain.com"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where Url has_all ("my.sharepoint.com","personal") and Subject has_all ("shared") and SenderFromDomain !in~ (exclusionDomain);`
