# *Using winget to download NGrok*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  T1211  |  Exploitation for Defense Evasion |  https://attack.mitre.org/techniques/T1211/|

#### Description
This detection attempts to identify ngrok being installed via the winget command to download via the windows store. This methods has proven to evade antivirus detection for potentially unwanted application.

#### Risk
Bypass security detections in place for Windows Defender antivirus.

#### Author <Optional>
- Gavin Knapp
- https://github.com/m4nbat
- @knappresearchlb
- https://www.linkedin.com/in/grjk83

#### References
- https://www.linkedin.com/posts/stephan-berger-59575a20a_dropping-ngrok-in-a-zip-file-onto-disk-results-activity-7390827794605293568-08W2

## Defender For Endpoint
```KQL
// Paste your query here
DeviceProcessEvents 
| where ProcessCommandLine has_all ("winget","ngrok","install","")
```
## Sentinel
```KQL
DeviceProcessEvents 
| where ProcessCommandLine has_all ("winget","ngrok","install","")
```
