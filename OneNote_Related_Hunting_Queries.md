# OneNote Suspicious Child Process and Activity Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |

#### Description
Detects suspicious child processes spawned by OneNote (onenote.exe), anomalous URL connections from OneNote, and potential OneNote-based phishing using shared links.

#### Risk
Adversaries have been distributing malware through OneNote files (.one) that launch malicious scripts when opened. OneNote spawning cmd.exe, PowerShell, or script interpreters is a strong indicator of compromise.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-march-2023/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "onenote.exe" and FileName in~ ("cmd.exe","powershell.exe",wscript.exe,"jscript.exe")
```

```KQL
DeviceEvents
| where ActionType =~ "BrowserLaunchedToOpenUrl" and InitiatingProcessFileName in~ ("onenote.exe") and RemoteUrl !startswith @"C:\Users\"
```

```KQL
let exclusionDomain = datatable(domain:string)["exampledomain.com"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where Url has_all ("my.sharepoint.com","personal") and Subject has_all ("shared") and SenderFromDomain !in~ (exclusionDomain);
```

## Sentinel
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "onenote.exe" and FileName in~ ("cmd.exe","powershell.exe",wscript.exe,"jscript.exe")
```

```KQL
DeviceEvents
| where ActionType =~ "BrowserLaunchedToOpenUrl" and InitiatingProcessFileName in~ ("onenote.exe") and RemoteUrl !startswith @"C:\Users\"
```

```KQL
let exclusionDomain = datatable(domain:string)["exampledomain.com"];
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where Url has_all ("my.sharepoint.com","personal") and Subject has_all ("shared") and SenderFromDomain !in~ (exclusionDomain);
```
