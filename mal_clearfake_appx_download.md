# ClearFake Detection Analytics - APPX Download

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |
| T1204 | User Execution | [User Execution](https://attack.mitre.org/techniques/T1204/) |

#### Description
Queries to detect the initial creation of malicious .appx files associated with ClearFake fake browser update campaigns. ClearFake is a fake update threat that delivers malware via compromised websites.

#### Risk
Detection of Explorer.exe creating AppxProvider.dll or AppxManifest.xml files may indicate a ClearFake infection in progress, where users have been tricked into installing a malicious application package.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Sekoia - ClearFake: a newcomer to the fake updates threats landscape](https://blog.sekoia.io/clearfake-a-newcomer-to-the-fake-updates-threats-landscape/)

## Defender For Endpoint

```KQL
//TTP: ClearFake - Possible creation of malicious .appx file
DeviceFileEvents
| where InitiatingProcessFileName =~ "Explorer.exe" and FileName in~ ("AppxProvider.dll","AppxManifest.xml")
```
