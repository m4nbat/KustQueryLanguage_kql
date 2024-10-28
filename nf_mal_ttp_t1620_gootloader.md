# PowerShell (powershell.exe) Performing a Reflective Load of a .NET Assembly

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) | 

#### Description
This detection rule identifies instances where PowerShell is loading a .NET assembly into memory for execution. This is indicative of threats like Gootloader, which utilize `System.Reflection` to load malicious assemblies for in-memory execution.

#### Risk
Reflective loading of assemblies is a technique often used by malicious actors to execute code stealthily. This detection captures potentially harmful .NET assembly loads, which could indicate malware such as Gootloader or other in-memory threats.

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
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("Reflection.Assembly", "Load", "byte[]")
