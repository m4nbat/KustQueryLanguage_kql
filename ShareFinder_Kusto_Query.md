# ShareFinder/Invoke-ShareFinder Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1135 | Network Share Discovery | [Network Share Discovery](https://attack.mitre.org/techniques/T1135/) |

#### Description
Detects the use of Invoke-ShareFinder (PowerSploit/PowerView) for network share discovery. The query decodes Base64-encoded PowerShell commands and looks for Invoke-ShareFinder strings.

#### Risk
Threat actors use Invoke-ShareFinder post-compromise to enumerate network shares for lateral movement and data exfiltration. This was observed in intrusions leading to ransomware deployment.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://thedfirreport.com/2023/01/23/sharefinder-how-threat-actors-discover-file-shares/
- https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/rules/windows/builtin/win_security_invoke_sharefinder_discovery.yml

## Defender For Endpoint
```KQL
//T1132 - T1132.001 - Base64 Encoded data. Adversaries may encode data to make the content of command and control traffic more difficult to detect. 
DeviceProcessEvents 
| where FileName =~ "powershell.exe"
//filter out FPs caused by the MDE SenseIR binary
| where InitiatingProcessParentFileName != "SenseIR.exe"
//filter out FPs caused by Nutanix
| where InitiatingProcessFolderPath !contains "c:\\program files\\nutanix"
//filter out noise caused by Windows Defender Exploit Guard
| where InitiatingProcessCommandLine !startswith "gc_worker.exe -a WindowsDefenderExploitGuard"
//filter out noise caused by ansible service account
| where InitiatingProcessAccountName != "svc-ansiblew"
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
| extend test = replace(@'\00', @'', DecodedString)
| extend DShash = hash_md5(DecodedString)
| where DShash != "765213794bd23a89ce9a84459a0cef80"
| where InitiatingProcessCommandLine contains "Invoke-ShareFinder" or DecodedString contains "Invoke-ShareFinder"
```

## Sentinel
```KQL
//T1132 - T1132.001 - Base64 Encoded data. Adversaries may encode data to make the content of command and control traffic more difficult to detect. 
DeviceProcessEvents 
| where FileName =~ "powershell.exe"
//filter out FPs caused by the MDE SenseIR binary
| where InitiatingProcessParentFileName != "SenseIR.exe"
//filter out FPs caused by Nutanix
| where InitiatingProcessFolderPath !contains "c:\\program files\\nutanix"
//filter out noise caused by Windows Defender Exploit Guard
| where InitiatingProcessCommandLine !startswith "gc_worker.exe -a WindowsDefenderExploitGuard"
//filter out noise caused by ansible service account
| where InitiatingProcessAccountName != "svc-ansiblew"
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
| extend test = replace(@'\00', @'', DecodedString)
| extend DShash = hash_md5(DecodedString)
| where DShash != "765213794bd23a89ce9a84459a0cef80"
| where InitiatingProcessCommandLine contains "Invoke-ShareFinder" or DecodedString contains "Invoke-ShareFinder"
```
