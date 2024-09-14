# SNAKE Malware Execution Tactics

## Query Information

#### MITRE ATT&CK Tactic(s)

| Tactic ID | Title    | Link    |
| ---  | --- | --- |
| TA0002 | Execution | [Execution](https://attack.mitre.org/tactics/TA0002/) |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| T1068 | Exploitation for Privilege Escalation | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) |

#### Description
Detects execution-related activities tied to the SNAKE malware as reported by CISA. This includes identifying kernel driver file indicators, suspicious filenames associated with SNAKE installation, specific command-line arguments, and installation binaries used during the malware execution.

#### Risk
The detection covers the execution of potentially harmful payloads and processes associated with the SNAKE malware. Attackers may leverage this for privilege escalation and to maintain persistence within compromised systems.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [CISA Report on Snake Malware](https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF)

---

## Queries

### Query 1 - SNAKE Malware Kernel Driver File Indicator

#### Description
This query detects the presence of a SNAKE malware kernel driver file indicator by monitoring the specific file path in `DeviceFileEvents`.

```KQL
DeviceFileEvents 
| where FolderPath =~ 'C:\Windows\System32\Com\Comadmin.dat'
```
### Query 2 - SNAKE Malware Installer Name Indicators
### Description
This query detects file names associated with the SNAKE malware installer as described in the CISA report, such as jpsetup.exe or jpinst.exe.

```KQL
DeviceFileEvents 
| where (FolderPath endswith '\jpsetup.exe' or FolderPath endswith '\jpinst.exe')
```
### Query 3 - Potential SNAKE Malware Installation CLI Arguments Indicator
#### Description
This query detects specific command line arguments seen during the installation of SNAKE malware. The command line pattern includes a sequence of alphanumeric characters in specific formats as observed by CISA.

```KQL
DeviceProcessEvents 
| where ProcessCommandLine matches regex '(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}' 
   or InitiatingProcessCommandLine matches regex '(?i)\s[a-fA-F0-9]{64}\s[a-fA-F0-9]{16}'
```

### Query 4 - Potential SNAKE Malware Installation Binary Indicator
#### Description
This query identifies the installation binary used by SNAKE malware during execution, focusing on files named jpsetup.exe and jpinst.exe and ensuring that the command line does not match certain benign processes or is not empty.

```KQL
DeviceProcessEvents 
| where ((FolderPath endswith '\jpsetup.exe' or FolderPath endswith '\jpinst.exe') 
         and not ((ProcessCommandLine in~ ('jpinst.exe', 'jpinst', 'jpsetup.exe', 'jpsetup')) 
         or ProcessCommandLine == '' or isempty(ProcessCommandLine)))
    or ((InitiatingProcessFolderPath endswith '\jpsetup.exe' or InitiatingProcessFolderPath endswith '\jpinst.exe') 
         and not ((InitiatingProcessCommandLine in~ ('jpinst.exe', 'jpinst', 'jpsetup.exe', 'jpsetup')) 
         or InitiatingProcessCommandLine == '' or isempty(InitiatingProcessCommandLine)))
```
