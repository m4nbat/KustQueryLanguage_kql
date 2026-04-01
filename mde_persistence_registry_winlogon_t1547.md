# Winlogon Registry Key Persistence

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1547 | Boot or Logon Autostart Execution | [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
Find modifications to Winlogon registry keys that are commonly abused for persistence. Attackers modify the `shell` or `userinit` values under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` to execute malicious binaries at every user logon.

#### Risk
Winlogon registry key modifications provide a stealthy persistence mechanism that executes attacker-controlled binaries during every logon. This technique survives reboots and is difficult to detect without monitoring registry changes to these specific keys.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Windows Persistence Using Winlogon](https://www.hackingarticles.in/windows-persistence-using-winlogon/)

## Defender For Endpoint
```KQL
DeviceRegistryEvents  
| where ActionType in~ ("RegistryValueSet","RegistryValueCreated")  
| where ( RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" or RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" ) and RegistryValueName in~ ("shell","userinit")
// review the key and associated key value to understand if malicious activity has taken place e.g. C:\Windows\system32\userinit.exe, C:\Windows\System32\evil.exe

```
