
# Day 11 - Suspicious PowerShell Commandline

## Description
Detection opportunity: PowerShell using invoke-expression to download content

This pseudo detection analytic identifies instances of PowerShell using invoke-expression to download content from an http URL. Adversaries attempting to deliver threats like LummaC2 use this function to download remotely hosted scripts and code for further exploitation of an endpoint. Note that legitimate package management and orchestration utilities like Chocolatey may use this function to update themselves.

### Example Script

```

N/A

```

## References
https://redcanary.com/blog/threat-intelligence/intelligence-insights-november-2024/

## Query MDE

``` KQL

DeviceProcessEvents
| where InitiatingProcessFileName has_any ("powershell.exe") and ProcessCommandLine has_any ("iex",".invoke","invoke-expression") and ProcessCommandLine has" http" 
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine


```



