# In-Memory Loading of PowerSploit Modules Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) |

#### Description
Detects in-memory loading of PowerSploit modules via CLR unbackedmodule loads. Monitors for PowerSploit-specific module names loaded by PowerShell without backing files on disk.

#### Risk
PowerSploit modules loaded in-memory are used for post-exploitation activities including privilege escalation, credential access, and persistence. In-memory execution evades file-based detection.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/PowerShellMafia/PowerSploit

## Defender For Endpoint
```KQL
//PowerSploit in memory module loads
let iocList = dynamic ([
"powersploit",
"Win32",
"DynamicAssembly", //can cause FPs
"ReflectedDelegate",
"SSPI",
"SSPI2",
"VaultUtil",
"VSSUtil",
"BlueScreen",
"Win32"
]);
DeviceEvents
| extend module = parse_json(AdditionalFields).ModuleILPathOrName
| where ActionType =~ "ClrUnbackedModuleLoaded" and module in~ (iocList) and InitiatingProcessFileName =~ "powershell.exe"
```

## Sentinel
```KQL
//PowerSploit in memory module loads
let iocList = dynamic ([
"powersploit",
"Win32",
"DynamicAssembly", //can cause FPs
"ReflectedDelegate",
"SSPI",
"SSPI2",
"VaultUtil",
"VSSUtil",
"BlueScreen",
"Win32"
]);
DeviceEvents
| extend module = parse_json(AdditionalFields).ModuleILPathOrName
| where ActionType =~ "ClrUnbackedModuleLoaded" and module in~ (iocList) and InitiatingProcessFileName =~ "powershell.exe"
```
