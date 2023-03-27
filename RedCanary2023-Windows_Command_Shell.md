# Red Canary Threat Report - Windows Command Shell

**Source:** https://redcanary.com/threat-detection-report/techniques/windows-command-shell/

**Experimental queries based on Red Canary threat report (Untested)**

## Tactic: Execution
## Technique: T1059.003 Windows Command Shell
**Source:** https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "mshta.exe" or InitiatingProcessFileName endswith "mshta.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ActionType in~ ("FileCreated","FileModified")`

## Tactic: Execution
## Technique: T1059.003 Windows Command Shell
**Source:** https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
DeviceFileEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe" or InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe")`

## Tactic:  DefenseEvasion
Identify commandlines with possible obfuscation

**pseudocode example:**  process == cmd.exe && command_includes [high numbers of the following characters] ('^' || '=' || '%' || '!' || '[' || '(' || ';' || ' ')
//test '%LOCALAPPDATA:~-3,1%md /c echo "tweet, tweet" > tweet.txt & type tweet.txt'

DeviceProcessEvents
| where InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe"
| extend a = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','^')
| extend b = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','=')
| extend c = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','%')
| extend d = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','!')
| extend e = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','[')
| extend f = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','(')
| extend g = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt',';')
| extend suspiciousChars = a + b + c + d + e + f + g
| where suspiciousChars > 4`

## Unusual or suspicious process ancestry
We have a lot of detection analytics that seek out suspicious or unusual process lineage spawning or spawning from cmd.exe. Many of them don’t often generate confirmed threat detections but can occasionally raise the flag on important threats, like Exchange compromises. One semi-common pattern in our library of analytics is suspicious process interactions between the Windows IIS worker process (w3wp.exe) and the command shell. The following amalgamation of analytics might help you detect a diverse array of malicious activity related to web server compromises.

**source:** https://redcanary.com/threat-detection-report/techniques/windows-command-shell/

**pseudocode example:** parent_process == w3wp.exe && process == cmd.exe && command_includes ('http://' || 'https://' || 'echo') || child_process == powershell.exe

let badCommands = datatable (command:string)[@"http://",@"https://","echo"];
DeviceProcessEvents
| where (InitiatingProcessParentFileName endswith "w3p.exe" or InitiatingProcessFileName endswith "w3p.exe") and (InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe") and ((InitiatingProcessFileName endswith "powershell.exe" or FileName endswith "powershell.exe") or (InitiatingProcessCommandLine has_any (badCommands) or ProcessCommandLine has_any (badCommands)))`


# Technique: Windows scheduled task create shell
Adversaries frequently establish persistence by using scheduled tasks to launch the Windows Command Shell. Detecting this behavior is relatively straightforward.
**Example commandline: **
schtasks /Create /SC DAILY /TN spawncmd /TR "cmd.exe /c echo tweet, tweet" /RU SYSTEM
let exampleCommand = datatable(commandline:string)['schtasks /Create /SC DAILY /TN spawncmd /TR "cmd.exe /c echo tweet, tweet" /RU SYSTEM'];
DeviceProcessEvents
| where ProcessName == "schtasks.exe"
| where CommandLine contains "create" and (CommandLine contains "cmd.exe /c" or CommandLine contains "cmd /c")
