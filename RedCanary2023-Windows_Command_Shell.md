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

`//#Tactic:  DefenseEvasion
// look at commandlines with possible obfuscation
// pseudocode example:  process == cmd.exe && command_includes [high numbers of the following characters] ('^' || '=' || '%' || '!' || '[' || '(' || ';' || ' ')
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
