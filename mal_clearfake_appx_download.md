# ClearFake Malware - Suspicious APPX File Creation Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects potential ClearFake malware activity via creation of .appx package files by Explorer.exe. ClearFake is a fake browser update campaign that delivers malicious APPX installers.

#### Risk
ClearFake injects malicious JavaScript into compromised websites to display fake browser update prompts. Clicking the update downloads a malicious APPX file that installs info-stealers.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/

## Defender For Endpoint
```KQL
//TTP: ClearFake - Possible creation of malicious .appx file
DeviceFileEvents
| where InitiatingProcessFileName =~ "Explorer.exe" and FileName in~ ("AppxProvider.dll","AppxManifest.xml")
```

## Sentinel
```KQL
//TTP: ClearFake - Possible creation of malicious .appx file
DeviceFileEvents
| where InitiatingProcessFileName =~ "Explorer.exe" and FileName in~ ("AppxProvider.dll","AppxManifest.xml")
```
