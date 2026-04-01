# In-Memory Load of PowerSploit Hack Tools

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) |

#### Description
Detects in-memory loading of PowerSploit modules via CLR (Common Language Runtime) unbacked module loads initiated by PowerShell. PowerSploit is a widely used PowerShell-based post-exploitation framework. The query monitors for CLR module loads matching known PowerSploit module names without a backing file on disk.

#### Risk
In-memory loading of PowerSploit modules bypasses traditional file-based AV/EDR detection. Detection of these CLR unbacked module loads from PowerShell indicates a threat actor is using memory-only techniques for post-exploitation activities such as privilege escalation, credential dumping, or persistence.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References

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
