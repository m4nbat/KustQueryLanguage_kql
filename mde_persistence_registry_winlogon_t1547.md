# Title
Winlogon Registry Key Persistence

# Tactics: 
- Persistence
- T1547:	Boot or Logon Autostart Execution
- T1547.001:	Registry Run Keys / Startup Folder

# Source
- https://www.hackingarticles.in/windows-persistence-using-winlogon/

# Description
Find Winlogon with outbound connections #MDE

Kusto:

```
DeviceRegistryEvents  
| where ActionType in~ ("RegistryValueSet","RegistryValueCreated")  
| where ( RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" or RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" ) and RegistryValueName in~ ("shell","userinit")
// review the key and associated key value to understand if malicious activity has taken place e.g. C:\Windows\system32\userinit.exe, C:\Windows\System32\evil.exe

```
