# Brute Ratel Sentinel Queries

## Kusto Queries

`// Possible Brute Ratel C4 Red Team Tool Detect (via DeviceFileEvents)
DeviceFileEvents 
| where ActionType =~ "FileCreated" 
| where FileName has_any ('fotos.iso','version.dll','brute-dll-agent.bin','versions.dll') or PreviousFileName has_any ('fotos.iso','version.dll','brute-dll-agent.bin','versions.dll') `

`// Possible Brute Ratel C4 Red Team Tool Detect (via file_event)
SecurityEvent |  where EventID == 11 | where (TargetFileName contains 'fotos.iso' or TargetFileName contains 'version.dll' or TargetFileName contains 'brute-dll-agent.bin' or TargetFileName contains 'versions.dll')`

//sentinel query for pipe BRC4
`SecurityEvent | where (PipeName endswith @'\wewe')`

## Grep

`grep -P '^(?:.*.*fotos\.iso.*|.*.*version\.dll.*|.*.*brute-dll-agent\.bin.*|.*.*versions\.dll.*)'`

`grep -P '^(?:.*.*\wewe)'`
