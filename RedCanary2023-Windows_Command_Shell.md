# Red Canary Threat Report - Windows Command Shell

## Source: https://redcanary.com/threat-detection-report/techniques/windows-command-shell/

## Experimental queries based on Red Canary threat report (Untested)

`//#Tactic: Execution
//#Technique: T1059.003 Windows Command Shell
//#Source: https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "mshta.exe" or InitiatingProcessFileName endswith "mshta.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ActionType in~ ("FileCreated","FileModified")`

`//#Tactic: Execution
//#Technique: T1059.003 Windows Command Shell
//#Source: https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe" or InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe")`
