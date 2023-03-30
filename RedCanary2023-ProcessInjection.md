# Process Injection
Process Injection continues to be a versatile tool that adversaries lean on to evade defensive controls and gain access to sensitive systems and information.

## Source
https://redcanary.com/threat-detection-report/techniques/process-injection/

## Kusto Queries

### Process executing sans command lines
One major tell for process injection is the absence of command lines. Detecting the absence of anything, including a command line, can be tricky, and this pseudo-analytic only works for processes where you expect corresponding commands. However, you may be able to iterate on the following amalgamation of detection logic to improve detection coverage. 

`DeviceProcessEvents
| where FileName in ('backgroundtaskhost.exe', 'svchost.exe', 'dllhost.exe', 'werfault.exe', 'searchprotocolhost.exe', 'wuauclt.exe', 'spoolsv.exe', 'rundll32.exe', 'regasm.exe', 'regsvr32.exe', 'regsvcs.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)`

## Network connections where there shouldn’t be
Detecting purely on processes making network connections has the potential to generate a torrent of false positives. However, it can also identify suspicious injection activity—particularly if you tune the logic to filter out the eccentricities in your specific environment.

`let FileNames = datatable(name:string)["notepad.exe","calc.exe"];
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (FileNames)`


## Injection into LSASS
Since injection into lsass.exe is common, impactful, and frequently suspicious, it deserves to be called out individually. To that point, it would be worth your time to determine and enumerate the processes in your environment that routinely or occasionally obtain a handle to lsass.exe. Any access outside of the baseline should be treated as suspicious. 

`TBD`


## Suspected LSASS Dump

`DeviceProcessEvents
| where InitiatingProcessCommandLine has_all ("procdump", "lsass") or InitiatingProcessCommandLine has_all ("rundll32", "comsvcs", "MiniDump")`
