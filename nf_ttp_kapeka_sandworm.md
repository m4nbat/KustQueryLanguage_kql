# Kapeka / Sandworm Malware Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) |
| T1053.005 | Scheduled Task/Job: Scheduled Task | [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |

#### Description
These queries detect TTPs associated with Kapeka and QUEUESEED malware used by the Sandworm threat actor (UAC-0133) targeting critical infrastructure facilities. Detections cover malware execution via batch files from AppData, scheduled task creation for "Sens Api" persistence, and registry run key modifications used for backdoor persistence.

#### Risk
Sandworm (UAC-0133) is a Russian state-sponsored APT targeting critical infrastructure. Kapeka and QUEUESEED malware provide persistent backdoor access that can lead to sabotage, data destruction, and disruption of critical services.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Detect FYI: UAC-0133 Sandworm Plans for Cyber Sabotage at Almost 20 Critical Infrastructure Facilities](https://medium.com/detect-fyi/uac-0133-sandworm-plans-for-cyber-sabotage-at-almost-20-critical-infrastructure-facilities-in-d923a6cbcef4)
- [UA CERT Article](https://cert.gov.ua/article/6278706)

## Defender For Endpoint

```KQL
//Example QUEUESEED for the batch file
//TTP QUEUESEED malware behaviour
DeviceProcessEvents
| where ( ProcessCommandLine has_all ("%COMSPEC%",@"/c",@"%APPDATA%\",".bat") or InitiatingProcessCommandLine has_all ("%COMSPEC%",@"/c",@"%APPDATA%\",".bat") )
```

```KQL
//Example KAPEKA for the batch file
//TTP KAPEKA malware behaviour
DeviceProcessEvents
| where ( ProcessCommandLine has_all (@"C:\Windows\system32\cmd.exe",@"/c",@"C:\Users\",@"\AppData\",".bat") or ProcessCommandLine has_all (@"C:\Windows\system32\cmd.exe",@"/c",@"C:\Users\",@"\AppData\",".bat") )
```

```KQL
//Additional registry entries for the backdoor for SENS API (KAPEKA)
//Scheduled Task Persistence Mechanisms
DeviceProcessEvents
| where ProcessCommandLine has_all ("/c","schtasks","/create","/sc","ONSTART","/tn","Sens Api","/f","/np","/tr",".wll")
```

```KQL
//Additional registry entries for the backdoor for SENS API (KAPEKA)
//Registry Persistence Mechanism
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey endswith @"\Windows\CurrentVersion\Run" and RegistryValueName =~ "Sens Api" and RegistryValueData has_all (@"rundll32.exe",@".wll",@"#1") 
```
