# Windows Script Host (wscript.exe) Executing Content from a User's AppData Folder

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: PowerShell | [Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) |

#### Description
This detection rule identifies instances where the Windows Script Host (`wscript.exe`) is executing a JavaScript (`.js`) file from the user's `AppData` folder. It aims to detect instances where a user may have unintentionally executed malicious content by opening a file associated with Gootloader.

#### Risk
This detection helps identify potential execution of malicious scripts from a user’s `AppData` folder, a common tactic for malware such as Gootloader. This behavior is a common sign of an initial compromise, often leading to further infection or data exfiltration.

#### Author
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)

#### References
- https://redcanary.com/wp-content/uploads/2022/05/Gootloader.pdf
- https://kqlquery.com/
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where FileName =~ "wscript.exe"
| where ProcessCommandLine has @"\appdata\" and ProcessCommandLine endswith ".js"
