# Script Execution from Explorer ZIP Function

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.007 | Command and Scripting Interpreter: JavaScript | [Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/) |
| T1566.001 | Phishing: Spearphishing Attachment | [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |

#### Description
Detection analytics identify scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.

#### Risk
Delivering malicious JavaScript or script files inside ZIP archives and executing them via Windows Explorer's built-in ZIP handler allows attackers to bypass email attachment filters and endpoint controls. This technique is actively used to drop second-stage malware and establish initial access.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Red Canary Intelligence Insights September 2023](https://redcanary.com/blog/intelligence-insights-september-2023/)

## Defender For Endpoint
```KQL
//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )
```

```KQL
//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "explorer.exe" and InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )
```

## Sentinel
```KQL
//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )
```

```KQL
//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "explorer.exe" and InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )
```
