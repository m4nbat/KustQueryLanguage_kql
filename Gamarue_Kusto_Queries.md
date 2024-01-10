# Gamarue
Gamarue is a worm that primarily spreads via USB drives. Despite its command and control (C2) infrastructure being disrupted in 2017, Gamarue keeps worming its way through many environments.

# Source: https://redcanary.com/threat-detection-report/threats/gamarue/

## Special characters in rundll32 command line
```
//Editors’ note: While the analysis and detection opportunities remain applicable, this threat page was written for a previous Threat Detection Report and has not been updated in 2022.
//Special characters in rundll32 command line
//ATT&CK technique(s): T1218.011 Signed Binary Proxy Execution: Rundll32
//ATT&CK tactic(s): Defense Evasion, Execution
//Details: The main detection analytic that helped us catch so much Gamarue was based on what we noticed about how Gamarue executed rundll32.exe. As we examined multiple Gamarue detections over time, we noticed that their rundll32.exe command lines consistently used the same number of characters in a repeatable pattern—25 characters followed by a period followed by 25 additional characters, then a comma and 16 more characters. For example:
//source: https://redcanary.com/threat-detection-report/threats/gamarue/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe" and InitiatingProcessCommandLine matches regex @'(?i)"C:\\Windows\\system32\\rundll32\.exe"\s+\\\S{25}\.\S{25},\S{16}'
```

## Windows Installer (msiexec.exe) external network connections
```
//Editors’ note: While the analysis and detection opportunities remain applicable, this threat page was written for a previous Threat Detection Report and has not been updated in 2022.
//Windows Installer (msiexec.exe) external network connections
//ATT&CK technique(s): T1218.007 Signed Binary Proxy Execution: Msiexec, T1055.012 Process Injection: Process Hollowing
//ATT&CK tactic(s): Defense Evasion, Command and Control
//Details: We observed Gamarue injecting into the signed Windows Installer msiexec.exe, which subsequently connected to C2 domains. Adversaries commonly use msiexec.exe to proxy the execution of malicious code through a trusted process. We detected Gamarue by looking for msiexec.exe without a command line making external network connections. Though many Gamarue C2 servers were disrupted in 2017, we found that some domains were active in 2020, like the one in the following example (4nbizac8[.]ru):
//source: https://redcanary.com/threat-detection-report/threats/gamarue/
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msiexec.exe" and isnotempty(RemoteUrl)
```

## ROT13 registry modifications LNK file
```
//Bonus forensic analysis opportunity
//ROT13 registry modifications
//ATT&CK technique(s): T1112 Modify Registry
//ATT&CK tactic(s): Defense Evasion/Execution
//Details: While this isn’t a detection opportunity, we wanted to share a tip for how we identify the source LNK that executed Gamarue in many of our detections. We observed that the parent process of rundll32.exe (often explorer.exe) usually creates a registry value in the UserAssist subkey. UserAssist tracks applications that were executed by a user and encodes data using the ROT13 cipher. Because Gamarue is often installed by a user clicking an LNK file, if you’re trying to figure out the source of Gamarue, check out the registry key HKEY_USERS\{SID}\Software\​Microsoft\Windows\CurrentVersion​\Explorer\UserAssist for any registry modifications ending in .yax—.yax is the ROT13 encoded value of .lnk. While this won’t be a good detection opportunity on its own, it could be helpful to look for this registry value if you’re responding to a Gamarue incident to figure out where it came from and clean the USB drive.
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryValueName endswith ".yax" and RegistryKey endswith @"\Software\​Microsoft\Windows\CurrentVersion​\Explorer\UserAssist"
```

