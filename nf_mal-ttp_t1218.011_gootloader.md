# Rundll32 (rundll32.exe) with No Command-Line Arguments

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | [Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/) |

#### Description
This detection rule identifies instances of `rundll32.exe` executing with no command-line arguments. This behavior is often indicative of malicious activity, such as injection by Cobalt Strike beacons, and has been observed in Gootloader infections.

#### Risk
Rundll32 executing without command-line arguments is uncommon in legitimate operations and often signifies injection techniques leveraged by malware, particularly Gootloader and Cobalt Strike.

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
DeviceNetworkEvents
| where FileName =~ "rundll32.exe"
| where isnull(ProcessCommandLine)

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
| where isnull(InitiatingProcessCommandLine)
