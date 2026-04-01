# Rundll32 Executing DLL from Windows Temp Directory

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | [Rundll32](https://attack.mitre.org/techniques/T1218/011/) |

#### Description
Detects rundll32.exe executing DLL files located in the Windows Temp directory. Malware commonly drops payloads to the Temp directory and uses rundll32 to execute them for defense evasion.

#### Risk
Loading DLLs from Temp directories via rundll32 is a common malware technique. It was observed in multiple threat campaigns including those using Cobalt Strike and various ransomware families.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-january-2023/

## Defender For Endpoint
```KQL
//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") and not(ProcessCommandLine has_any (trustedDlls))
```

```KQL
//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where ((InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") or (InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine contains @"windows\temp")) and not(InitiatingProcessCommandLine has_any (trustedDlls) or ProcessCommandLine has_any (trustedDlls))
```

## Sentinel
```KQL
//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") and not(ProcessCommandLine has_any (trustedDlls))
```

```KQL
//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where ((InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") or (InitiatingProcessParentFileName =~ "rundll32.exe" and InitiatingProcessCommandLine contains @"windows\temp")) and not(InitiatingProcessCommandLine has_any (trustedDlls) or ProcessCommandLine has_any (trustedDlls))
```
